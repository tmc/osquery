/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_endpointsecurity);

REGISTER(EndpointSecurityPublisher, "event_publisher", "endpointsecurity")

Status EndpointSecurityPublisher::setUp() {
  if (__builtin_available(macos 10.15, *)) {
    if (FLAGS_disable_endpointsecurity) {
      return Status::failure(1,
                             "EndpointSecurity is disabled via configuration");
    }

    auto handler = ^(es_client_t* client, const es_message_t* message) {
      handleMessage(message);
    };

    auto result = es_new_client(&es_client_, handler);

    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
      es_client_success_ = true;
      return Status::success();
    } else {
      return Status::failure(1, getEsNewClientErrorMessage(result));
    }
  } else {
    return Status::failure(
        1, "EndpointSecurity is only available on macOS 10.15 and higher");
  }
}

void EndpointSecurityPublisher::configure() {
  if (es_client_ == nullptr) {
    return;
  }

  auto cache = es_clear_cache(es_client_);
  if (cache != ES_CLEAR_CACHE_RESULT_SUCCESS) {
    VLOG(1) << "Couldn't clear cache for EndpointSecurity client";
    return;
  }

  std::vector<es_event_type_t> event_types;
  for (auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    auto events = sc->es_event_subscriptions_;
    // Add all event types from this subscription
    event_types.insert(event_types.end(), events.begin(), events.end());
  }
  
  // Remove duplicate event types
  std::sort(event_types.begin(), event_types.end());
  event_types.erase(std::unique(event_types.begin(), event_types.end()), event_types.end());
  
  if (!event_types.empty()) {
    auto es_sub = es_subscribe(es_client_, &event_types[0], event_types.size());
    if (es_sub != ES_RETURN_SUCCESS) {
      VLOG(1) << "Couldn't subscribe to EndpointSecurity subsystem";
    } else {
      VLOG(1) << "Successfully subscribed to " << event_types.size() 
              << " EndpointSecurity event types";
    }
  }
}

void EndpointSecurityPublisher::tearDown() {
  if (es_client_ == nullptr) {
    return;
  }
  es_unsubscribe_all(es_client_);

  if (es_client_success_) {
    auto result = es_delete_client(es_client_);
    if (result != ES_RETURN_SUCCESS) {
      VLOG(1) << "endpointsecurity: error tearing down es_client";
    }
    es_client_ = nullptr;
  }
}

void EndpointSecurityPublisher::handleMessage(const es_message_t* message) {
  if (message == nullptr) {
    return;
  }

  // Only handle NOTIFY events here, not AUTH
  if (message->action_type == ES_ACTION_TYPE_AUTH) {
    return;
  }

  auto ec = createEventContext();

  ec->version = message->version;
  if (ec->version >= 2) {
    ec->seq_num = message->seq_num;
  }

  if (ec->version >= 4) {
    ec->global_seq_num = message->global_seq_num;
  }

  getProcessProperties(message->process, ec);
  ec->es_event = message->event_type;

  switch (message->event_type) {
  // Process lifecycle events
  case ES_EVENT_TYPE_NOTIFY_EXEC: {
    ec->event_type = "exec";

    getProcessProperties(message->event.exec.target, ec);
    ec->argc = es_exec_arg_count(&message->event.exec);
    {
      std::stringstream args;
      for (auto i = 0; i < ec->argc; i++) {
        auto arg = es_exec_arg(&message->event.exec, i);
        auto s = getStringFromToken(&arg);
        appendQuotedString(args, s, ' ');
      }
      ec->args = args.str();
    }

    ec->envc = es_exec_env_count(&message->event.exec);
    {
      std::stringstream envs;
      for (auto i = 0; i < ec->envc; i++) {
        auto env = es_exec_env(&message->event.exec, i);
        auto s = getStringFromToken(&env);
        appendQuotedString(envs, s, ' ');
      }
      ec->envs = envs.str();
    }

    if (ec->version >= 3) {
      ec->cwd = getStringFromToken(&message->event.exec.cwd->path);
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_FORK: {
    ec->event_type = "fork";
    ec->child_pid = audit_token_to_pid(message->event.fork.child->audit_token);
  } break;
  case ES_EVENT_TYPE_NOTIFY_EXIT: {
    ec->event_type = "exit";
    ec->exit_code = message->event.exit.stat;
  } break;
  
  // Signal events
  case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
    ec->event_type = "signal";
    ec->signal_number = message->event.signal.sig;
    if (message->event.signal.target) {
      ec->metadata["target_pid"] = std::to_string(audit_token_to_pid(message->event.signal.target->audit_token));
    }
  } break;
  
  // UID/GID events
  case ES_EVENT_TYPE_NOTIFY_SETUID: {
    ec->event_type = "setuid";
    ec->target_uid = message->event.setuid.uid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETEUID: {
    ec->event_type = "seteuid";
    ec->target_uid = message->event.seteuid.uid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETREUID: {
    ec->event_type = "setreuid";
    ec->target_uid = message->event.setreuid.ruid;
    ec->target_euid = message->event.setreuid.euid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETEGID: {
    ec->event_type = "setegid";
    ec->target_gid = message->event.setegid.gid;
  } break;
  case ES_EVENT_TYPE_NOTIFY_SETREGID: {
    ec->event_type = "setregid";
    ec->target_gid = message->event.setregid.rgid;
    ec->target_egid = message->event.setregid.egid;
  } break;
  
  // Network events
  case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: {
    ec->event_type = "uipc_bind";
    if (message->event.uipc_bind.dir) {
      ec->path = getStringFromToken(&message->event.uipc_bind.dir->path);
      if (message->event.uipc_bind.filename) {
        ec->path += "/";
        ec->path += getStringFromToken(message->event.uipc_bind.filename);
      }
    }
    ec->socket_domain = std::to_string(message->event.uipc_bind.domain);
    ec->socket_type = std::to_string(message->event.uipc_bind.type);
    ec->socket_protocol = std::to_string(message->event.uipc_bind.protocol);
  } break;
  case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: {
    ec->event_type = "uipc_connect";
    if (message->event.uipc_connect.dir) {
      ec->path = getStringFromToken(&message->event.uipc_connect.dir->path);
      if (message->event.uipc_connect.filename) {
        ec->path += "/";
        ec->path += getStringFromToken(message->event.uipc_connect.filename);
      }
    }
    ec->socket_domain = std::to_string(message->event.uipc_connect.domain);
    ec->socket_type = std::to_string(message->event.uipc_connect.type);
    ec->socket_protocol = std::to_string(message->event.uipc_connect.protocol);
  } break;
  
  // Mount events
  case ES_EVENT_TYPE_NOTIFY_MOUNT: {
    ec->event_type = "mount";
    if (message->event.mount.statfs) {
      ec->mount_path = message->event.mount.statfs->f_mntonname;
      ec->mount_type = message->event.mount.statfs->f_fstypename;
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_UNMOUNT: {
    ec->event_type = "unmount";
    if (message->event.unmount.statfs) {
      ec->mount_path = message->event.unmount.statfs->f_mntonname;
      ec->mount_type = message->event.unmount.statfs->f_fstypename;
    }
  } break;
  
  // Remote thread events
  case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: {
    ec->event_type = "remote_thread_create";
    if (message->event.remote_thread_create.target) {
      ec->metadata["target_pid"] = std::to_string(
        audit_token_to_pid(message->event.remote_thread_create.target->audit_token));
    }
    ec->metadata["thread_state"] = std::to_string(
      message->event.remote_thread_create.thread_state);
  } break;
  
  // SSH events
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: {
    ec->event_type = "openssh_login";
    ec->ssh_login_username = 
      getStringFromToken(message->event.openssh_login.username);
    ec->metadata["success"] = 
      message->event.openssh_login.success ? "true" : "false";
    ec->metadata["result_type"] = std::to_string(
      message->event.openssh_login.result_type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: {
    ec->event_type = "openssh_logout";
    ec->ssh_login_username = 
      getStringFromToken(message->event.openssh_logout.username);
  } break;
  
  // ScreenSharing events
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: {
    ec->event_type = "screensharing_attach";
    ec->screensharing_type = "attach";
    if (message->event.screensharing_attach.viewer_appliance) {
      ec->screensharing_viewer_app_path = 
        getStringFromToken(&message->event.screensharing_attach.viewer_appliance->executable->path);
    }
    ec->metadata["success"] = 
      message->event.screensharing_attach.success ? "true" : "false";
    ec->metadata["type"] = std::to_string(
      message->event.screensharing_attach.type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: {
    ec->event_type = "screensharing_detach";
    ec->screensharing_type = "detach";
    if (message->event.screensharing_detach.viewer_appliance) {
      ec->screensharing_viewer_app_path = 
        getStringFromToken(&message->event.screensharing_detach.viewer_appliance->executable->path);
    }
    ec->metadata["type"] = std::to_string(
      message->event.screensharing_detach.type);
  } break;
  
  // Su/sudo events
  case ES_EVENT_TYPE_NOTIFY_SU: {
    ec->event_type = "su";
    if (message->event.su.from_username && message->event.su.to_username) {
      ec->su_from_username = 
        getStringFromToken(message->event.su.from_username);
      ec->su_to_username = 
        getStringFromToken(message->event.su.to_username);
    }
    ec->metadata["success"] = 
      message->event.su.success ? "true" : "false";
  } break;
  case ES_EVENT_TYPE_NOTIFY_SUDO: {
    ec->event_type = "sudo";
    ec->sudo_success = message->event.sudo.success;
    if (message->event.sudo.command) {
      ec->sudo_command = 
        getStringFromToken(message->event.sudo.command);
    }
  } break;
  
  // Authentication events
  case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: {
    ec->event_type = "authentication";
    ec->metadata["success"] = 
      message->event.authentication.success ? "true" : "false";
    ec->metadata["type"] = std::to_string(
      message->event.authentication.type);
  } break;
  case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION: {
    ec->event_type = "authorization";
    if (message->event.authorization.right) {
      ec->auth_right = 
        getStringFromToken(message->event.authorization.right);
    }
    ec->metadata["result_type"] = std::to_string(
      message->event.authorization.result_type);
  } break;
  
  // Profile events
  case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD: {
    ec->event_type = "profile_add";
    if (message->event.profile_add.identifier) {
      ec->profile_identifier = 
        getStringFromToken(message->event.profile_add.identifier);
    }
    if (message->event.profile_add.uuid) {
      ec->profile_uuid = 
        getStringFromToken(message->event.profile_add.uuid);
    }
  } break;
  case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE: {
    ec->event_type = "profile_remove";
    if (message->event.profile_remove.identifier) {
      ec->profile_identifier = 
        getStringFromToken(message->event.profile_remove.identifier);
    }
    if (message->event.profile_remove.uuid) {
      ec->profile_uuid = 
        getStringFromToken(message->event.profile_remove.uuid);
    }
  } break;
  
  // XPC events  
  case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: {
    ec->event_type = "xpc_connect";
    if (message->event.xpc_connect.service_name) {
      ec->metadata["service_name"] = 
        getStringFromToken(message->event.xpc_connect.service_name);
    }
  } break;
  
  // Handle other events
  default: {
    // Generic event type extraction
    std::string event_type_name = "unknown";
    for (const auto& pair : kESEventNameMap) {
      if (pair.second == message->event_type) {
        event_type_name = pair.first;
        break;
      }
    }
    ec->event_type = event_type_name;
    
    VLOG(1) << "EndpointSecurity unhandled event type: " << event_type_name;
  } break;
  }

  EventFactory::fire<EndpointSecurityPublisher>(ec);
}

bool EndpointSecurityPublisher::shouldFire(
    const EndpointSecuritySubscriptionContextRef& sc,
    const EndpointSecurityEventContextRef& ec) const {
  return true;
}

} // namespace osquery
