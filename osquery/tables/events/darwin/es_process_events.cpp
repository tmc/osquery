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
#include <osquery/events/events.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

REGISTER(ESProcessEventSubscriber, "event_subscriber", "es_process_events");

Status ESProcessEventSubscriber::init() {
  if (__builtin_available(macos 10.15, *)) {
    auto sc = createSubscriptionContext();

    // Get all enabled event types from the configuration system
    sc->es_event_subscriptions_ = getEnabledEventTypes();

    // Only pass events that should be handled by this subscriber
    // to avoid cluttering the logs during verbose mode
    VLOG(1) << "ESProcessEventSubscriber subscribed to "
            << sc->es_event_subscriptions_.size() << " event types";

    subscribe(&ESProcessEventSubscriber::Callback, sc);

    return Status::success();
  } else {
    return Status::failure(1, "Only available on macOS 10.15 and higher");
  }
}

Status ESProcessEventSubscriber::Callback(
    const EndpointSecurityEventContextRef& ec,
    const EndpointSecuritySubscriptionContextRef& sc) {
  Row r;

  // Standard process information fields
  r["version"] = INTEGER(ec->version);
  r["seq_num"] = BIGINT(ec->seq_num);
  r["global_seq_num"] = BIGINT(ec->global_seq_num);
  r["event_type"] = ec->event_type;
  r["pid"] = BIGINT(ec->pid);
  r["pidversion"] = INTEGER(ec->pidversion);
  r["parent"] = BIGINT(ec->parent);
  r["parent_pidversion"] = INTEGER(ec->parent_pidversion);
  r["original_parent"] = BIGINT(ec->original_parent);
  r["session_id"] = BIGINT(ec->session_id);
  r["responsible_pid"] = BIGINT(ec->responsible_pid);
  r["responsible_pidversion"] = INTEGER(ec->responsible_pidversion);
  r["path"] = ec->path;
  r["cwd"] = ec->cwd;
  r["uid"] = BIGINT(ec->uid);
  r["euid"] = BIGINT(ec->euid);
  r["gid"] = BIGINT(ec->gid);
  r["egid"] = BIGINT(ec->egid);
  r["signing_id"] = ec->signing_id;
  r["team_id"] = ec->team_id;
  r["cdhash"] = ec->cdhash;
  r["codesigning_flags"] = ec->codesigning_flags;
  r["platform_binary"] = (ec->platform_binary) ? INTEGER(1) : INTEGER(0);
  r["username"] = ec->username;

  // Process events (exec, fork, exit)
  if (ec->event_type == "exec") {
    r["cmdline"] = ec->args;
    r["cmdline_count"] = BIGINT(ec->argc);
    r["env"] = ec->envs;
    r["env_count"] = BIGINT(ec->envc);
  } else if (ec->event_type == "fork") {
    r["child_pid"] = BIGINT(ec->child_pid);
  } else if (ec->event_type == "exit") {
    r["exit_code"] = INTEGER(ec->exit_code);
  }

  // UID/GID change events
  else if (ec->event_type == "setuid" || ec->event_type == "seteuid") {
    r["target_uid"] = BIGINT(ec->target_uid);
  } else if (ec->event_type == "setreuid") {
    r["target_uid"] = BIGINT(ec->target_uid);
    r["target_euid"] = BIGINT(ec->target_euid);
  } else if (ec->event_type == "setgid" || ec->event_type == "setegid") {
    r["target_gid"] = BIGINT(ec->target_gid);
  } else if (ec->event_type == "setregid") {
    r["target_gid"] = BIGINT(ec->target_gid);
    r["target_egid"] = BIGINT(ec->target_egid);
  }

  // Signal events
  else if (ec->event_type == "signal") {
    r["signal_number"] = INTEGER(ec->signal_number);
    if (!ec->metadata.empty() && ec->metadata.count("target_pid") > 0) {
      r["target_pid"] = ec->metadata.at("target_pid");
    }
  }

  // Socket events
  else if (ec->event_type == "uipc_bind" || ec->event_type == "uipc_connect") {
    r["socket_domain"] = ec->socket_domain;
    r["socket_type"] = ec->socket_type;
    r["socket_protocol"] = ec->socket_protocol;
  }

  // Mount events
  else if (ec->event_type == "mount" || ec->event_type == "unmount") {
    r["mount_path"] = ec->mount_path;
    r["mount_type"] = ec->mount_type;
  }

  // SSH events
  else if (ec->event_type == "openssh_login" ||
           ec->event_type == "openssh_logout") {
    r["ssh_login_username"] = ec->ssh_login_username;

    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("result_type") > 0) {
        r["result_type"] = ec->metadata.at("result_type");
      }
    }
  }

  // ScreenSharing events
  else if (ec->event_type == "screensharing_attach" ||
           ec->event_type == "screensharing_detach") {
    r["screensharing_type"] = ec->screensharing_type;
    r["screensharing_viewer_app_path"] = ec->screensharing_viewer_app_path;

    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("type") > 0) {
        r["connection_type"] = ec->metadata.at("type");
      }
    }
  }

  // SU events
  else if (ec->event_type == "su") {
    r["su_from_username"] = ec->su_from_username;
    r["su_to_username"] = ec->su_to_username;

    if (!ec->metadata.empty() && ec->metadata.count("success") > 0) {
      r["success"] = ec->metadata.at("success");
    }
  }

  // Sudo events
  else if (ec->event_type == "sudo") {
    r["sudo_command"] = ec->sudo_command;
    r["success"] = ec->sudo_success ? "true" : "false";
  }

  // Authentication events
  else if (ec->event_type == "authentication") {
    if (!ec->metadata.empty()) {
      if (ec->metadata.count("success") > 0) {
        r["success"] = ec->metadata.at("success");
      }
      if (ec->metadata.count("type") > 0) {
        r["auth_type"] = ec->metadata.at("type");
      }
    }
  }

  // Authorization events
  else if (ec->event_type == "authorization") {
    r["auth_right"] = ec->auth_right;

    if (!ec->metadata.empty() && ec->metadata.count("result_type") > 0) {
      r["result_type"] = ec->metadata.at("result_type");
    }
  }

  // Profile events
  else if (ec->event_type == "profile_add" ||
           ec->event_type == "profile_remove") {
    r["profile_identifier"] = ec->profile_identifier;
    r["profile_uuid"] = ec->profile_uuid;
  }

  // XPC events
  else if (ec->event_type == "xpc_connect") {
    if (!ec->metadata.empty() && ec->metadata.count("service_name") > 0) {
      r["service_name"] = ec->metadata.at("service_name");
    }
  }

  // Include all remaining metadata values
  for (const auto& meta_pair : ec->metadata) {
    if (r.count(meta_pair.first) == 0) {
      r[meta_pair.first] = meta_pair.second;
    }
  }

  sc->row_list = {r};
  if (!sc->row_list.empty()) {
    addBatch(sc->row_list);
  }

  return Status::success();
}

} // namespace osquery
