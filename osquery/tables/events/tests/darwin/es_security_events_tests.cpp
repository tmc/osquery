/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/tables/events/darwin/es_security_events.cpp>

namespace osquery {
namespace {

class ESSecurityEventsTests : public testing::Test {
 protected:
  void SetUp() override {
    // Create a subscription context for testing
    sc_ = std::make_shared<EndpointSecuritySubscriptionContext>();

    // Create a message for testing (a simplified stub)
    message_ = {};
    process_ = {};

    // Set up basic message structure
    message_.process = &process_;
    message_.time.tv_sec = 1234567890;
    message_.version = 4;
    message_.global_seq_num = 12345;
  }

  void TearDown() override {
    // Clean up
  }

  // Stub implementation of structures
  EndpointSecuritySubscriptionContextRef sc_;
  es_message_t message_;
  es_process_t process_;
};

TEST_F(ESSecurityEventsTests, CallbackTest) {
  // Create a security event context with basic information
  auto ec = std::make_shared<EndpointSecurityEventContext>();
  ec->event_type = "test_event";
  ec->category = "memory";
  ec->severity = "high";
  ec->eid = "test-uuid-1234";
  ec->pid = 1234;
  ec->path = "/usr/bin/test";
  ec->description = "Test security event";

  // For memory events
  ec->address = "0x12345678";
  ec->protection = "rwx";
  ec->size = 4096;

  // Call the callback
  ESSecurityEventSubscriber subscriber;
  auto status = subscriber.Callback(ec, sc_);

  // Verify the callback was successful
  EXPECT_TRUE(status.ok());

  // Verify row was added to the subscription context
  EXPECT_EQ(sc_->row_list.size(), 1U);

  // Verify row contents
  if (!sc_->row_list.empty()) {
    auto row = sc_->row_list[0];

    EXPECT_EQ(row["event_type"], "test_event");
    EXPECT_EQ(row["category"], "memory");
    EXPECT_EQ(row["severity"], "high");
    EXPECT_EQ(row["eid"], "test-uuid-1234");
    EXPECT_EQ(row["pid"], "1234");
    EXPECT_EQ(row["path"], "/usr/bin/test");
    EXPECT_EQ(row["description"], "Test security event");

    // Check memory-specific fields
    EXPECT_EQ(row["address"], "0x12345678");
    EXPECT_EQ(row["protection"], "rwx");
    EXPECT_EQ(row["size"], "4096");
  }
}

TEST_F(ESSecurityEventsTests, GetSecurityEventDataTest) {
  if (__builtin_available(macos 10.15, *)) {
    // Only run the test on macOS 10.15 or newer

    auto ec = std::make_shared<EndpointSecurityEventContext>();

    // Test memory event handling
    if (__builtin_available(macos 11.0, *)) {
      // Memory events (mmap, mprotect)
      message_.event_type = ES_EVENT_TYPE_NOTIFY_MMAP;

      // Stub for mmap event
      es_event_mmap_t mmap_event = {};
      mmap_event.protection = PROT_READ | PROT_WRITE | PROT_EXEC;
      mmap_event.size = 4096;
      mmap_event.address = reinterpret_cast<void*>(0x12345678);
      message_.event.mmap = &mmap_event;

      // Get security event data
      auto status =
          ESSecurityEventSubscriber::getSecurityEventData(&message_, ec);
      EXPECT_TRUE(status.ok());

      // Verify event data
      EXPECT_EQ(ec->event_type, "mmap");
      EXPECT_EQ(ec->protection, "rwx");
      EXPECT_EQ(ec->size, 4096);
      EXPECT_NE(ec->address.find("0x"), std::string::npos);
    }

    // Test privilage event handling
    message_.event_type = ES_EVENT_TYPE_NOTIFY_SETUID;

    // Stub for setuid event
    es_event_setuid_t setuid_event = {};
    if (__builtin_available(macos 12.0, *)) {
      setuid_event.euid = 500;
    } else {
      setuid_event.uid = 500;
    }
    message_.event.setuid = setuid_event;

    // Get security event data
    auto status =
        ESSecurityEventSubscriber::getSecurityEventData(&message_, ec);
    EXPECT_TRUE(status.ok());

    // Verify event data
    EXPECT_EQ(ec->event_type, "setuid");
    EXPECT_EQ(ec->target_uid, 500);
  }
}

TEST_F(ESSecurityEventsTests, InitTest) {
  if (__builtin_available(macos 10.15, *)) {
    // Test initialization of the subscriber
    ESSecurityEventSubscriber subscriber;
    auto status = subscriber.init();

    // Always expect success on macOS 10.15+
    EXPECT_TRUE(status.ok());
  }
}

// Additional helper function tests

TEST_F(ESSecurityEventsTests, generateEventIdTest) {
  // Test UUID generation
  std::string uuid1 = generateEventId();
  std::string uuid2 = generateEventId();

  // Each UUID should be 36 characters (including hyphens)
  EXPECT_EQ(uuid1.length(), 36U);
  EXPECT_EQ(uuid2.length(), 36U);

  // UUIDs should be unique
  EXPECT_NE(uuid1, uuid2);

  // Check for proper UUID format (8-4-4-4-12 hex digits)
  EXPECT_TRUE(std::regex_match(
      uuid1,
      std::regex(
          "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")));
}

TEST_F(ESSecurityEventsTests, isFileEventTest) {
  // Test file event detection
  EXPECT_TRUE(isFileEvent(ES_EVENT_TYPE_NOTIFY_CREATE));
  EXPECT_TRUE(isFileEvent(ES_EVENT_TYPE_NOTIFY_RENAME));
  EXPECT_TRUE(isFileEvent(ES_EVENT_TYPE_NOTIFY_CHMOD));

  // Test non-file events
  EXPECT_FALSE(isFileEvent(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_FALSE(isFileEvent(ES_EVENT_TYPE_NOTIFY_FORK));
  EXPECT_FALSE(isFileEvent(ES_EVENT_TYPE_NOTIFY_SOCKET));
}

TEST_F(ESSecurityEventsTests, isAuthenticationEventTest) {
  // Test authentication event detection
  EXPECT_TRUE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
  EXPECT_TRUE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN));
  EXPECT_TRUE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_SU));
  EXPECT_TRUE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_SUDO));

  // Test non-authentication events
  EXPECT_FALSE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_FALSE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_SOCKET));
  EXPECT_FALSE(isAuthenticationEvent(ES_EVENT_TYPE_NOTIFY_MMAP));
}

} // namespace
} // namespace osquery