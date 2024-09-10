# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [google/api/http.proto](#google_api_http-proto)
    - [CustomHttpPattern](#google-api-CustomHttpPattern)
    - [Http](#google-api-Http)
    - [HttpRule](#google-api-HttpRule)
  
- [google/api/annotations.proto](#google_api_annotations-proto)
    - [File-level Extensions](#google_api_annotations-proto-extensions)
  
- [Scalar Value Types](#scalar-value-types)



<a name="google_api_http-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## google/api/http.proto



<a name="google-api-CustomHttpPattern"></a>

### CustomHttpPattern
A custom pattern is used for defining custom HTTP verb.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| kind | [string](#string) |  | The name of this custom HTTP verb. |
| path | [string](#string) |  | The path matched by this custom verb. |






<a name="google-api-Http"></a>

### Http
Defines the HTTP configuration for an API service. It contains a list of
[HttpRule][google.api.HttpRule], each specifying the mapping of an RPC method
to one or more HTTP REST API methods.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| rules | [HttpRule](#google-api-HttpRule) | repeated | A list of HTTP configuration rules that apply to individual API methods.

**NOTE:** All service configuration rules follow &#34;last one wins&#34; order. |
| fully_decode_reserved_expansion | [bool](#bool) |  | When set to true, URL path parameters will be fully URI-decoded except in cases of single segment matches in reserved expansion, where &#34;%2F&#34; will be left encoded.

The default behavior is to not decode RFC 6570 reserved characters in multi segment matches. |






<a name="google-api-HttpRule"></a>

### HttpRule
gRPC Transcoding

gRPC Transcoding is a feature for mapping between a gRPC method and one or
more HTTP REST endpoints. It allows developers to build a single API service
that supports both gRPC APIs and REST APIs. Many systems, including [Google
APIs](https://github.com/googleapis/googleapis),
[Cloud Endpoints](https://cloud.google.com/endpoints), [gRPC
Gateway](https://github.com/grpc-ecosystem/grpc-gateway),
and [Envoy](https://github.com/envoyproxy/envoy) proxy support this feature
and use it for large scale production services.

`HttpRule` defines the schema of the gRPC/REST mapping. The mapping specifies
how different portions of the gRPC request message are mapped to the URL
path, URL query parameters, and HTTP request body. It also controls how the
gRPC response message is mapped to the HTTP response body. `HttpRule` is
typically specified as an `google.api.http` annotation on the gRPC method.

Each mapping specifies a URL path template and an HTTP method. The path
template may refer to one or more fields in the gRPC request message, as long
as each field is a non-repeated field with a primitive (non-message) type.
The path template controls how fields of the request message are mapped to
the URL path.

Example:

    service Messaging {
      rpc GetMessage(GetMessageRequest) returns (Message) {
        option (google.api.http) = {
            get: &#34;/v1/{name=messages/*}&#34;
        };
      }
    }
    message GetMessageRequest {
      string name = 1; // Mapped to URL path.
    }
    message Message {
      string text = 1; // The resource content.
    }

This enables an HTTP REST to gRPC mapping as below:

- HTTP: `GET /v1/messages/123456`
- gRPC: `GetMessage(name: &#34;messages/123456&#34;)`

Any fields in the request message which are not bound by the path template
automatically become HTTP query parameters if there is no HTTP request body.
For example:

    service Messaging {
      rpc GetMessage(GetMessageRequest) returns (Message) {
        option (google.api.http) = {
            get:&#34;/v1/messages/{message_id}&#34;
        };
      }
    }
    message GetMessageRequest {
      message SubMessage {
        string subfield = 1;
      }
      string message_id = 1; // Mapped to URL path.
      int64 revision = 2;    // Mapped to URL query parameter `revision`.
      SubMessage sub = 3;    // Mapped to URL query parameter `sub.subfield`.
    }

This enables a HTTP JSON to RPC mapping as below:

- HTTP: `GET /v1/messages/123456?revision=2&amp;sub.subfield=foo`
- gRPC: `GetMessage(message_id: &#34;123456&#34; revision: 2 sub:
SubMessage(subfield: &#34;foo&#34;))`

Note that fields which are mapped to URL query parameters must have a
primitive type or a repeated primitive type or a non-repeated message type.
In the case of a repeated type, the parameter can be repeated in the URL
as `...?param=A&amp;param=B`. In the case of a message type, each field of the
message is mapped to a separate parameter, such as
`...?foo.a=A&amp;foo.b=B&amp;foo.c=C`.

For HTTP methods that allow a request body, the `body` field
specifies the mapping. Consider a REST update method on the
message resource collection:

    service Messaging {
      rpc UpdateMessage(UpdateMessageRequest) returns (Message) {
        option (google.api.http) = {
          patch: &#34;/v1/messages/{message_id}&#34;
          body: &#34;message&#34;
        };
      }
    }
    message UpdateMessageRequest {
      string message_id = 1; // mapped to the URL
      Message message = 2;   // mapped to the body
    }

The following HTTP JSON to RPC mapping is enabled, where the
representation of the JSON in the request body is determined by
protos JSON encoding:

- HTTP: `PATCH /v1/messages/123456 { &#34;text&#34;: &#34;Hi!&#34; }`
- gRPC: `UpdateMessage(message_id: &#34;123456&#34; message { text: &#34;Hi!&#34; })`

The special name `*` can be used in the body mapping to define that
every field not bound by the path template should be mapped to the
request body.  This enables the following alternative definition of
the update method:

    service Messaging {
      rpc UpdateMessage(Message) returns (Message) {
        option (google.api.http) = {
          patch: &#34;/v1/messages/{message_id}&#34;
          body: &#34;*&#34;
        };
      }
    }
    message Message {
      string message_id = 1;
      string text = 2;
    }


The following HTTP JSON to RPC mapping is enabled:

- HTTP: `PATCH /v1/messages/123456 { &#34;text&#34;: &#34;Hi!&#34; }`
- gRPC: `UpdateMessage(message_id: &#34;123456&#34; text: &#34;Hi!&#34;)`

Note that when using `*` in the body mapping, it is not possible to
have HTTP parameters, as all fields not bound by the path end in
the body. This makes this option more rarely used in practice when
defining REST APIs. The common usage of `*` is in custom methods
which don&#39;t use the URL at all for transferring data.

It is possible to define multiple HTTP methods for one RPC by using
the `additional_bindings` option. Example:

    service Messaging {
      rpc GetMessage(GetMessageRequest) returns (Message) {
        option (google.api.http) = {
          get: &#34;/v1/messages/{message_id}&#34;
          additional_bindings {
            get: &#34;/v1/users/{user_id}/messages/{message_id}&#34;
          }
        };
      }
    }
    message GetMessageRequest {
      string message_id = 1;
      string user_id = 2;
    }

This enables the following two alternative HTTP JSON to RPC mappings:

- HTTP: `GET /v1/messages/123456`
- gRPC: `GetMessage(message_id: &#34;123456&#34;)`

- HTTP: `GET /v1/users/me/messages/123456`
- gRPC: `GetMessage(user_id: &#34;me&#34; message_id: &#34;123456&#34;)`

Rules for HTTP mapping

1. Leaf request fields (recursive expansion nested messages in the request
   message) are classified into three categories:
   - Fields referred by the path template. They are passed via the URL path.
   - Fields referred by the [HttpRule.body][google.api.HttpRule.body]. They
   are passed via the HTTP
     request body.
   - All other fields are passed via the URL query parameters, and the
     parameter name is the field path in the request message. A repeated
     field can be represented as multiple query parameters under the same
     name.
 2. If [HttpRule.body][google.api.HttpRule.body] is &#34;*&#34;, there is no URL
 query parameter, all fields
    are passed via URL path and HTTP request body.
 3. If [HttpRule.body][google.api.HttpRule.body] is omitted, there is no HTTP
 request body, all
    fields are passed via URL path and URL query parameters.

Path template syntax

    Template = &#34;/&#34; Segments [ Verb ] ;
    Segments = Segment { &#34;/&#34; Segment } ;
    Segment  = &#34;*&#34; | &#34;**&#34; | LITERAL | Variable ;
    Variable = &#34;{&#34; FieldPath [ &#34;=&#34; Segments ] &#34;}&#34; ;
    FieldPath = IDENT { &#34;.&#34; IDENT } ;
    Verb     = &#34;:&#34; LITERAL ;

The syntax `*` matches a single URL path segment. The syntax `**` matches
zero or more URL path segments, which must be the last part of the URL path
except the `Verb`.

The syntax `Variable` matches part of the URL path as specified by its
template. A variable template must not contain other variables. If a variable
matches a single path segment, its template may be omitted, e.g. `{var}`
is equivalent to `{var=*}`.

The syntax `LITERAL` matches literal text in the URL path. If the `LITERAL`
contains any reserved character, such characters should be percent-encoded
before the matching.

If a variable contains exactly one path segment, such as `&#34;{var}&#34;` or
`&#34;{var=*}&#34;`, when such a variable is expanded into a URL path on the client
side, all characters except `[-_.~0-9a-zA-Z]` are percent-encoded. The
server side does the reverse decoding. Such variables show up in the
[Discovery
Document](https://developers.google.com/discovery/v1/reference/apis) as
`{var}`.

If a variable contains multiple path segments, such as `&#34;{var=foo/*}&#34;`
or `&#34;{var=**}&#34;`, when such a variable is expanded into a URL path on the
client side, all characters except `[-_.~/0-9a-zA-Z]` are percent-encoded.
The server side does the reverse decoding, except &#34;%2F&#34; and &#34;%2f&#34; are left
unchanged. Such variables show up in the
[Discovery
Document](https://developers.google.com/discovery/v1/reference/apis) as
`{&#43;var}`.

Using gRPC API Service Configuration

gRPC API Service Configuration (service config) is a configuration language
for configuring a gRPC service to become a user-facing product. The
service config is simply the YAML representation of the `google.api.Service`
proto message.

As an alternative to annotating your proto file, you can configure gRPC
transcoding in your service config YAML files. You do this by specifying a
`HttpRule` that maps the gRPC method to a REST endpoint, achieving the same
effect as the proto annotation. This can be particularly useful if you
have a proto that is reused in multiple services. Note that any transcoding
specified in the service config will override any matching transcoding
configuration in the proto.

The following example selects a gRPC method and applies an `HttpRule` to it:

    http:
      rules:
        - selector: example.v1.Messaging.GetMessage
          get: /v1/messages/{message_id}/{sub.subfield}

Special notes

When gRPC Transcoding is used to map a gRPC to JSON REST endpoints, the
proto to JSON conversion must follow the [proto3
specification](https://developers.google.com/protocol-buffers/docs/proto3#json).

While the single segment variable follows the semantics of
[RFC 6570](https://tools.ietf.org/html/rfc6570) Section 3.2.2 Simple String
Expansion, the multi segment variable **does not** follow RFC 6570 Section
3.2.3 Reserved Expansion. The reason is that the Reserved Expansion
does not expand special characters like `?` and `#`, which would lead
to invalid URLs. As the result, gRPC Transcoding uses a custom encoding
for multi segment variables.

The path variables **must not** refer to any repeated or mapped field,
because client libraries are not capable of handling such variable expansion.

The path variables **must not** capture the leading &#34;/&#34; character. The reason
is that the most common use case &#34;{var}&#34; does not capture the leading &#34;/&#34;
character. For consistency, all path variables must share the same behavior.

Repeated message fields must not be mapped to URL query parameters, because
no client library can support such complicated mapping.

If an API needs to use a JSON array for request or response body, it can map
the request or response body to a repeated field. However, some gRPC
Transcoding implementations may not support this feature.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector | [string](#string) |  | Selects a method to which this rule applies.

Refer to [selector][google.api.DocumentationRule.selector] for syntax details. |
| get | [string](#string) |  | Maps to HTTP GET. Used for listing and getting information about resources. |
| put | [string](#string) |  | Maps to HTTP PUT. Used for replacing a resource. |
| post | [string](#string) |  | Maps to HTTP POST. Used for creating a resource or performing an action. |
| delete | [string](#string) |  | Maps to HTTP DELETE. Used for deleting a resource. |
| patch | [string](#string) |  | Maps to HTTP PATCH. Used for updating a resource. |
| custom | [CustomHttpPattern](#google-api-CustomHttpPattern) |  | The custom pattern is used for specifying an HTTP method that is not included in the `pattern` field, such as HEAD, or &#34;*&#34; to leave the HTTP method unspecified for this rule. The wild-card rule is useful for services that provide content to Web (HTML) clients. |
| body | [string](#string) |  | The name of the request field whose value is mapped to the HTTP request body, or `*` for mapping all request fields not captured by the path pattern to the HTTP body, or omitted for not having any HTTP request body.

NOTE: the referred field must be present at the top-level of the request message type. |
| response_body | [string](#string) |  | Optional. The name of the response field whose value is mapped to the HTTP response body. When omitted, the entire response message will be used as the HTTP response body.

NOTE: The referred field must be present at the top-level of the response message type. |
| additional_bindings | [HttpRule](#google-api-HttpRule) | repeated | Additional HTTP bindings for the selector. Nested bindings must not contain an `additional_bindings` field themselves (that is, the nesting may only be one level deep). |





 

 

 

 



<a name="google_api_annotations-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## google/api/annotations.proto


 

 


<a name="google_api_annotations-proto-extensions"></a>

### File-level Extensions
| Extension | Type | Base | Number | Description |
| --------- | ---- | ---- | ------ | ----------- |
| http | HttpRule | .google.protobuf.MethodOptions | 72295728 | See `HttpRule`. |

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

