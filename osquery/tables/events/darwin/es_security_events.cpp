/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <os/availability.h>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/events/events.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>

namespace osquery {

// Define flags for controlling which event types are enabled
FLAG(bool,
     enable_es_network_events,
     false,
     "Enable EndpointSecurity network event monitoring");

FLAG(bool,
     enable_es_memory_events,
     false,
     "Enable EndpointSecurity memory protection event monitoring");

FLAG(bool,
     enable_es_system_events,
     false,
     "Enable EndpointSecurity system event monitoring");

FLAG(bool,
     enable_es_privilege_events,
     false,
     "Enable EndpointSecurity privilege event monitoring");

// Forward declaration of the event subscriber class
class ESSecurityEventSubscriber
    : public EventSubscriber<EndpointSecurityPublisher> {
 public:
  ESSecurityEventSubscriber() {
    setName("es_security_events");
  }

  Status init() override;
  Status Callback(const EndpointSecurityEventContextRef& ec,
                  const EndpointSecuritySubscriptionContextRef& sc);

  // Handler to extract security event data from an ES message
  static Status getSecurityEventData(const es_message_t* message,
                                     EndpointSecurityEventContextRef& ec);
};

REGISTER(ESSecurityEventSubscriber, "event_subscriber", "es_security_events");

/**
 * @brief Initialize the SecurityEventSubscriber by creating subscriptions
 *        to the appropriate event types based on OS version and flags.
 */
Status ESSecurityEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    // Memory events (macOS 11+)
    if (FLAGS_enable_es_memory_events && __builtin_available(macos 11.0, *)) {
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_MMAP);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_MPROTECT);
    }

    // Network events
    if (FLAGS_enable_es_network_events && osSupportsNetworkEvents()) {
      // Add Unix domain socket events (available on all supported macOS
      // versions)
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_BIND);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT);

      // On pre-macOS 15, we can add all network events
      if (!(__builtin_available(macos 15.0, *))) {
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SOCKET);
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_CONNECT);
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_BIND);
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_LISTEN);
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_ACCEPT);
      }
    }

    // System events
    if (FLAGS_enable_es_system_events) {
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_KEXTLOAD);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD);

      // Add sysctl event if not on macOS 15+
      if (!(__builtin_available(macos 15.0, *))) {
        sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SYSCTL);
      }
    }

    // Privilege events
    if (FLAGS_enable_es_privilege_events) {
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETUID);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETEUID);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETREUID);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETGID);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETEGID);
      sc->es_event_subscriptions_.push_back(ES_EVENT_TYPE_NOTIFY_SETREGID);
    }

    subscribe(&ESSecurityEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

/**
 * @brief Process security events from EndpointSecurity and store them.
 *
 * @param message Pointer to the EndpointSecurity message
 * @param ec Reference to the event context to populate
 * @return Status indicating success or failure
 */
Status ESSecurityEventSubscriber::getSecurityEventData(
    const es_message_t* message, EndpointSecurityEventContextRef& ec) {
  if (message == nullptr || ec == nullptr) {
    return Status::failure(1, "Invalid message or context");
  }

  // Fill in common event metadata
  ec->es_event = message->event_type;
  auto event_time = static_cast<long long>(message->time.tv_sec);
  ec->time = event_time;
  getBaseProcessProperties(message->process, ec);

  // Get category, severity, and name from es_event_categories
  ec->category = getEventCategory(message->event_type);
  ec->severity = getEventSeverity(message->event_type);
  ec->description = getEventName(message->event_type);
  ec->eid = generateEventId(); // Create a unique ID for this event

  // Default initialize network fields
  ec->local_address = "";
  ec->remote_address = "";
  ec->local_port = 0;
  ec->remote_port = 0;

  // Default initialize memory fields
  ec->address = "";
  ec->protection = "";
  ec->size = 0;

  // Default initialize kext fields
  ec->kext_path = "";
  ec->kext_version = "";
  ec->kext_id = "";

  // Process different security event types
  switch (message->event_type) {
  // Memory protection events
  case ES_EVENT_TYPE_NOTIFY_MMAP: {
    if (__builtin_available(macos 11.0, *)) {
      ec->event_type = "mmap";

      // Get memory address as string
      std::stringstream ss;
      ss << std::hex << message->event.mmap->address;
      ec->address = "0x" + ss.str();

      // Get memory protection flags
      std::string prot = "";
      if (message->event.mmap->protection & PROT_READ) {
        prot += "r";
      }
      if (message->event.mmap->protection & PROT_WRITE) {
        prot += "w";
      }
      if (message->event.mmap->protection & PROT_EXEC) {
        prot += "x";
      }
      ec->protection = prot;

      // Get memory size
      ec->size = static_cast<int64_t>(message->event.mmap->size);
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_MPROTECT: {
    if (__builtin_available(macos 11.0, *)) {
      ec->event_type = "mprotect";

      // Get memory address as string
      std::stringstream ss;
      ss << std::hex << message->event.mprotect->address;
      ec->address = "0x" + ss.str();

      // Get memory protection flags
      std::string prot = "";
      if (message->event.mprotect->protection & PROT_READ) {
        prot += "r";
      }
      if (message->event.mprotect->protection & PROT_WRITE) {
        prot += "w";
      }
      if (message->event.mprotect->protection & PROT_EXEC) {
        prot += "x";
      }
      ec->protection = prot;

      // Get memory size
      ec->size = static_cast<int64_t>(message->event.mprotect->size);
    }
    break;
  }

  // Network events
  case ES_EVENT_TYPE_NOTIFY_SOCKET: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "socket";

      // Get socket family
      int domain = message->event.socket->domain;
      switch (domain) {
      case AF_INET:
        ec->family = "IPv4";
        break;
      case AF_INET6:
        ec->family = "IPv6";
        break;
      case AF_UNIX:
        ec->family = "UNIX";
        break;
      default:
        ec->family = std::to_string(domain);
        break;
      }

      // Get socket type
      int type = message->event.socket->type;
      switch (type) {
      case SOCK_STREAM:
        ec->socket_type = "stream";
        break;
      case SOCK_DGRAM:
        ec->socket_type = "dgram";
        break;
      case SOCK_RAW:
        ec->socket_type = "raw";
        break;
      default:
        ec->socket_type = std::to_string(type);
        break;
      }

      // Get protocol
      ec->protocol = message->event.socket->protocol;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_CONNECT: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "connect";

      // Attempt to extract remote address info from sockaddr
      if (message->event.connect->remote->sa_family == AF_INET) {
        const struct sockaddr_in* addr =
            reinterpret_cast<const struct sockaddr_in*>(
                message->event.connect->remote);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        ec->remote_address = ip_str;
        ec->remote_port = ntohs(addr->sin_port);
        ec->family = "IPv4";
      } else if (message->event.connect->remote->sa_family == AF_INET6) {
        const struct sockaddr_in6* addr =
            reinterpret_cast<const struct sockaddr_in6*>(
                message->event.connect->remote);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        ec->remote_address = ip_str;
        ec->remote_port = ntohs(addr->sin6_port);
        ec->family = "IPv6";
      } else if (message->event.connect->remote->sa_family == AF_UNIX) {
        ec->family = "UNIX";
        // Unix domain sockets don't have IPs or ports
      }
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_BIND: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "bind";

      // Attempt to extract local address info from sockaddr
      if (message->event.bind->local->sa_family == AF_INET) {
        const struct sockaddr_in* addr =
            reinterpret_cast<const struct sockaddr_in*>(
                message->event.bind->local);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        ec->local_address = ip_str;
        ec->local_port = ntohs(addr->sin_port);
        ec->family = "IPv4";
      } else if (message->event.bind->local->sa_family == AF_INET6) {
        const struct sockaddr_in6* addr =
            reinterpret_cast<const struct sockaddr_in6*>(
                message->event.bind->local);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        ec->local_address = ip_str;
        ec->local_port = ntohs(addr->sin6_port);
        ec->family = "IPv6";
      } else if (message->event.bind->local->sa_family == AF_UNIX) {
        ec->family = "UNIX";
        // Unix domain sockets don't have IPs or ports
      }
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_LISTEN: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "listen";
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_ACCEPT: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "accept";
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: {
    ec->event_type = "uipc_bind";
    ec->family = "UNIX";

    // Try to get the Unix domain socket path
    if (message->event.uipc_bind->dir != nullptr &&
        message->event.uipc_bind->dir->path.length > 0) {
      const auto& path_token = message->event.uipc_bind->dir->path;
      if (path_token.length > 0 && path_token.data != nullptr) {
        ec->local_address = std::string(path_token.data, path_token.length);
      }
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
    ec->event_type = "uipc_connect";
    ec->family = "UNIX";

    // Try to get the Unix domain socket path
    if (message->event.uipc_connect->dir != nullptr &&
        message->event.uipc_connect->dir->path.length > 0) {
      const auto& path_token = message->event.uipc_connect->dir->path;
      if (path_token.length > 0 && path_token.data != nullptr) {
        ec->remote_address = std::string(path_token.data, path_token.length);
      }
    }
    break;
  }

  // Kernel extension events
  case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: {
    ec->event_type = "kextload";

    // Extract kext information
    if (message->event.kextload->identifier.length > 0 &&
        message->event.kextload->identifier.data != nullptr) {
      ec->kext_id = std::string(message->event.kextload->identifier.data,
                                message->event.kextload->identifier.length);
    }

    // Version may not be available in all versions of the API
    ec->kext_version = "";

    // Get the kext path
    if (message->event.kextload->kext != nullptr &&
        message->event.kextload->kext->path.length > 0) {
      const auto& path_token = message->event.kextload->kext->path;
      if (path_token.length > 0 && path_token.data != nullptr) {
        ec->kext_path = std::string(path_token.data, path_token.length);
      }
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: {
    ec->event_type = "kextunload";

    // Extract kext information
    if (message->event.kextunload->identifier.length > 0 &&
        message->event.kextunload->identifier.data != nullptr) {
      ec->kext_id = std::string(message->event.kextunload->identifier.data,
                                message->event.kextunload->identifier.length);
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SYSCTL: {
    if (!(__builtin_available(macos 15.0, *))) {
      ec->event_type = "sysctl";
      // Add any sysctl-specific information here
    }
    break;
  }

  // Privilege events
  case ES_EVENT_TYPE_NOTIFY_SETUID: {
    ec->event_type = "setuid";

    // Handle macOS version differences for uid/euid field naming
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_uid = message->event.setuid.euid;
    } else {
      ec->target_uid = message->event.setuid.uid;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SETEUID: {
    ec->event_type = "seteuid";

    // Handle macOS version differences for uid/euid field naming
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_uid = message->event.seteuid.euid;
    } else {
      ec->target_uid = message->event.seteuid.uid;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SETREUID: {
    ec->event_type = "setreuid";

    // We'll store the effective UID as the target
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_uid = message->event.setreuid.euid;
    } else {
      ec->target_uid = message->event.setreuid.uid;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SETGID: {
    ec->event_type = "setgid";

    // Handle macOS version differences for gid/egid field naming
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_gid = message->event.setgid.egid;
    } else {
      ec->target_gid = message->event.setgid.gid;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SETEGID: {
    ec->event_type = "setegid";

    // Handle macOS version differences for gid/egid field naming
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_gid = message->event.setegid.egid;
    } else {
      ec->target_gid = message->event.setegid.gid;
    }
    break;
  }

  case ES_EVENT_TYPE_NOTIFY_SETREGID: {
    ec->event_type = "setregid";

    // We'll store the effective GID as the target
    if (useEuidFieldsForSetters() && __builtin_available(macos 12.0, *)) {
      ec->target_gid = message->event.setregid.egid;
    } else {
      ec->target_gid = message->event.setregid.gid;
    }
    break;
  }

  default:
    return Status::failure(1, "Unsupported security event type");
  }

  return Status::success();
}

Status ESSecurityEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  // Process security event
  Row r;

  r["time"] = BIGINT(ec->time);
  r["eid"] = SQL_TEXT(ec->eid);
  r["event_type"] = SQL_TEXT(ec->event_type);
  r["category"] = SQL_TEXT(ec->category);
  r["severity"] = SQL_TEXT(ec->severity);
  r["pid"] = BIGINT(ec->pid);
  r["parent"] = BIGINT(ec->parent);
  r["path"] = SQL_TEXT(ec->path);
  r["username"] = SQL_TEXT(ec->username);
  r["description"] = SQL_TEXT(ec->description);

  // Memory events fields
  r["address"] = SQL_TEXT(ec->address);
  r["protection"] = SQL_TEXT(ec->protection);
  r["size"] = BIGINT(ec->size);

  // Network events fields
  r["local_address"] = SQL_TEXT(ec->local_address);
  r["remote_address"] = SQL_TEXT(ec->remote_address);
  r["local_port"] = INTEGER(ec->local_port);
  r["remote_port"] = INTEGER(ec->remote_port);
  r["family"] = SQL_TEXT(ec->family);
  r["protocol"] = INTEGER(ec->protocol);
  r["socket_type"] = SQL_TEXT(ec->socket_type);

  // System events fields
  r["kext_path"] = SQL_TEXT(ec->kext_path);
  r["kext_version"] = SQL_TEXT(ec->kext_version);
  r["kext_id"] = SQL_TEXT(ec->kext_id);

  // Privilege events fields
  r["uid"] = BIGINT(ec->uid);
  r["euid"] = BIGINT(ec->euid);
  r["gid"] = BIGINT(ec->gid);
  r["egid"] = BIGINT(ec->egid);
  r["target_uid"] = BIGINT(ec->target_uid);
  r["target_gid"] = BIGINT(ec->target_gid);

  // Add the row to our subscription context
  sc->row_list.push_back(r);
  return Status::success();
}

namespace tables {

class ESSecurityEvents {
 public:
  static QueryData genTable(QueryContext& context) {
    QueryData results;
    auto es_security_events =
        EventFactory::getEventSubscriber("es_security_events");
    if (es_security_events != nullptr) {
      auto subscriber =
          dynamic_cast<ESSecurityEventSubscriber*>(es_security_events.get());
      if (subscriber != nullptr) {
        // Get time ranges to query
        auto time_constraint = context.constraints["time"].getAll(EQUALS);

        // Get all batched events within time range
        if (context.constraints["time"].exists(EQUALS)) {
          for (const auto& time : time_constraint) {
            subscriber->getEvents(time, results);
          }
        } else {
          // If no time constraint, get all events in the buffer
          subscriber->getEvents(results);
        }
      }
    }
    return results;
  }
};

} // namespace tables
} // namespace osquery