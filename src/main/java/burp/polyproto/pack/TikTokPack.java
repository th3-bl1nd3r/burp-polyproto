package burp.polyproto.pack;

import burp.polyproto.core.Direction;
import burp.polyproto.protobuf.ProtoSchema;

/**
 * TikTok / ByteDance vendor pack: the IM SDK protobuf field-name overlays (com.bytedance.im.core.proto.*)
 * and the Frontier WebSocket envelope descriptor. Field tags = squareup-wire constructor-arg order,
 * recovered via JEB. Contributes only schemas; the matching rules live in builtins.json.
 */
public final class TikTokPack {

    public static void install(SchemaPacks packs) {
        // ---- IM protobuf overlays ----
        ProtoSchema msgIdIndex = new ProtoSchema("MessageIDIndexEntry")
                .f(1, "server_message_id").f(2, "index_in_conversation");

        ProtoSchema messageBody = new ProtoSchema("MessageBody")
                .f(1, "conversation_id").f(2, "conversation_type").f(3, "server_message_id")
                .f(4, "index_in_conversation").f(5, "conversation_short_id").f(6, "message_type")
                .f(7, "sender").f(8, "content").f(9, "ext").f(10, "create_time").f(11, "version")
                .f(12, "status").f(13, "order_in_conversation").f(14, "sec_sender").f(15, "property_list")
                .f(16, "user_profile").f(17, "index_in_conversation_v2").f(18, "reference_info")
                .f(19, "index_in_conversation_v1").f(20, "content_pb").f(21, "scene")
                .f(22, "conv_rank_update_rule").f(23, "ttl").f(24, "media_info_list")
                .f(25, "pre_conversation_index").f(26, "biz_persistent_extra").f(27, "index_in_user_inbox")
                .f(28, "app_id").f(29, "source_vregion");

        ProtoSchema getMessagesReq = new ProtoSchema("GetMessagesRequestBody")
                .f(1, "conversation_id").f(2, "conversation_type").f(3, "conversation_short_id")
                .f(4, "entries", msgIdIndex);
        ProtoSchema getConvInfoV2Req = new ProtoSchema("GetConversationInfoV2RequestBody")
                .f(1, "conversation_id").f(2, "conversation_short_id").f(3, "conversation_type").f(4, "ext");
        ProtoSchema batchReadIndexReq = new ProtoSchema("BatchGetConversationParticipantsReadIndexRequestBody")
                .f(1, "conversation_id").f(2, "conversation_short_id").f(3, "request_from").f(4, "min_index_required");
        ProtoSchema msgsPerUserComboReq = new ProtoSchema("MessagesPerUserComboRequestBody")
                .f(1, "inboxes").f(2, "status_adapter_map").f(3, "last_pull_time");
        ProtoSchema getMessagesResp = new ProtoSchema("GetMessagesResponseBody")
                .f(1, "messages", messageBody).f(2, "errors");

        ProtoSchema requestBody = new ProtoSchema("RequestBody")
                .f(204, "messages_per_user_combo_body", msgsPerUserComboReq)
                .f(608, "get_conversation_info_v2_body", getConvInfoV2Req)
                .f(2038, "batch_get_read_index_body", batchReadIndexReq)
                .f(2200, "get_messages_body", getMessagesReq);
        ProtoSchema responseBody = new ProtoSchema("ResponseBody")
                .f(2200, "get_messages_body", getMessagesResp);

        // Field layout verified via JEB (com.bytedance.im.core.proto.Request / Response,
        // squareup-wire constructor-arg order = tag order).
        ProtoSchema request = new ProtoSchema("Request")
                .f(1, "cmd").f(2, "sequence_id").f(3, "sdk_version").f(4, "token").f(5, "refer")
                .f(6, "inbox_type").f(7, "build_number").f(8, "body", requestBody).f(9, "device_id")
                .f(10, "channel").f(11, "device_platform").f(12, "device_type").f(13, "os_version")
                .f(14, "version_code").f(15, "headers").f(16, "config_id").f(17, "token_info")
                .f(18, "auth_type").f(19, "msg_trace").f(20, "retry_count").f(21, "source");
        ProtoSchema response = new ProtoSchema("Response")
                .f(1, "cmd").f(2, "sequence_id").f(3, "status_code").f(4, "error_desc").f(5, "inbox_type")
                .f(6, "body", responseBody).f(7, "log_id").f(8, "headers").f(9, "start_time_stamp")
                .f(10, "request_arrived_time").f(11, "server_execution_end_time").f(12, "retry_count")
                .f(13, "server_start_time").f(14, "region").f(15, "expected_user_id");

        packs.putProto("tiktok.im", Direction.REQUEST, request);
        packs.putProto("tiktok.im", Direction.RESPONSE, response);

        // ---- Frontier WebSocket envelope ----
        packs.putEnvelope("tiktok.frontier", new EnvelopeDescriptor());
    }

    private TikTokPack() {}
}
