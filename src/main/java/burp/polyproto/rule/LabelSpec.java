package burp.polyproto.rule;

import java.util.List;

/** How to extract a short human label for the decoded tab (e.g. Meta's fb_api_req_friendly_name). */
public final class LabelSpec {
    public String from;               // form-json-field | path-regex | header | proto-field | envelope-field
    public String key;                // field name / header name
    public String pattern;            // regex (for path-regex)
    public String template;           // e.g. "{value} (doc_id={doc_id})"; {1},{2} = regex groups
    public List<String> alsoExtract;  // extra keys usable in the template
}
