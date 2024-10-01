# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [api/v1/transferable_account.proto](#api_v1_transferable_account-proto)
    - [Account](#api-v1-Account)
    - [AccountOperationRequest](#api-v1-AccountOperationRequest)
    - [ApproveAddressRequest](#api-v1-ApproveAddressRequest)
    - [ApproveAddressResponse](#api-v1-ApproveAddressResponse)
    - [CreateAccountRequest](#api-v1-CreateAccountRequest)
    - [CreateAccountResponse](#api-v1-CreateAccountResponse)
    - [DeleteAccountRequest](#api-v1-DeleteAccountRequest)
    - [DeleteAccountResponse](#api-v1-DeleteAccountResponse)
    - [GetAccountRequest](#api-v1-GetAccountRequest)
    - [GetAccountResponse](#api-v1-GetAccountResponse)
    - [IsAccountLockedRequest](#api-v1-IsAccountLockedRequest)
    - [IsAccountLockedResponse](#api-v1-IsAccountLockedResponse)
    - [IsApprovedRequest](#api-v1-IsApprovedRequest)
    - [IsApprovedResponse](#api-v1-IsApprovedResponse)
    - [IsOwnerRequest](#api-v1-IsOwnerRequest)
    - [IsOwnerResponse](#api-v1-IsOwnerResponse)
    - [LockAccountRequest](#api-v1-LockAccountRequest)
    - [RevokeApprovalRequest](#api-v1-RevokeApprovalRequest)
    - [RevokeApprovalResponse](#api-v1-RevokeApprovalResponse)
    - [SignRequest](#api-v1-SignRequest)
    - [SignResponse](#api-v1-SignResponse)
    - [TimedSignature](#api-v1-TimedSignature)
    - [TransferAccountRequest](#api-v1-TransferAccountRequest)
    - [TransferAccountResponse](#api-v1-TransferAccountResponse)
    - [UnlockAccountRequest](#api-v1-UnlockAccountRequest)
    - [UnlockAccountResponse](#api-v1-UnlockAccountResponse)
  
    - [Curve](#api-v1-Curve)
  
    - [AccountService](#api-v1-AccountService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="api_v1_transferable_account-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## api/v1/transferable_account.proto



<a name="api-v1-Account"></a>

### Account
Structs


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |
| owner | [string](#string) |  |  |
| public_key_x | [string](#string) |  |  |
| public_key_y | [string](#string) |  |  |
| curve | [Curve](#api-v1-Curve) |  |  |
| is_locked | [bool](#bool) |  |  |






<a name="api-v1-AccountOperationRequest"></a>

### AccountOperationRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |
| proof | [TimedSignature](#api-v1-TimedSignature) |  |  |






<a name="api-v1-ApproveAddressRequest"></a>

### ApproveAddressRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |
| address | [string](#string) |  |  |






<a name="api-v1-ApproveAddressResponse"></a>

### ApproveAddressResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |






<a name="api-v1-CreateAccountRequest"></a>

### CreateAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| proof | [TimedSignature](#api-v1-TimedSignature) |  |  |






<a name="api-v1-CreateAccountResponse"></a>

### CreateAccountResponse
Responses


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |
| account_id | [string](#string) |  |  |






<a name="api-v1-DeleteAccountRequest"></a>

### DeleteAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |






<a name="api-v1-DeleteAccountResponse"></a>

### DeleteAccountResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |






<a name="api-v1-GetAccountRequest"></a>

### GetAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |






<a name="api-v1-GetAccountResponse"></a>

### GetAccountResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account | [Account](#api-v1-Account) |  |  |






<a name="api-v1-IsAccountLockedRequest"></a>

### IsAccountLockedRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |






<a name="api-v1-IsAccountLockedResponse"></a>

### IsAccountLockedResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| result | [bool](#bool) |  |  |






<a name="api-v1-IsApprovedRequest"></a>

### IsApprovedRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |
| address | [string](#string) |  |  |






<a name="api-v1-IsApprovedResponse"></a>

### IsApprovedResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| result | [bool](#bool) |  |  |






<a name="api-v1-IsOwnerRequest"></a>

### IsOwnerRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account_id | [string](#string) |  |  |
| address | [string](#string) |  |  |






<a name="api-v1-IsOwnerResponse"></a>

### IsOwnerResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| result | [bool](#bool) |  |  |






<a name="api-v1-LockAccountRequest"></a>

### LockAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |






<a name="api-v1-RevokeApprovalRequest"></a>

### RevokeApprovalRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |
| address | [string](#string) |  |  |






<a name="api-v1-RevokeApprovalResponse"></a>

### RevokeApprovalResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |






<a name="api-v1-SignRequest"></a>

### SignRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |
| data | [string](#string) |  | hex encoded |






<a name="api-v1-SignResponse"></a>

### SignResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |
| signature | [string](#string) |  | hex encoded |






<a name="api-v1-TimedSignature"></a>

### TimedSignature
Requests


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| valid_for | [uint64](#uint64) |  | unix timestamp |
| message_hash | [string](#string) |  | hex encoded |
| signature | [string](#string) |  | hex encoded |
| signer | [string](#string) |  | address |






<a name="api-v1-TransferAccountRequest"></a>

### TransferAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |
| to | [string](#string) |  |  |






<a name="api-v1-TransferAccountResponse"></a>

### TransferAccountResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |






<a name="api-v1-UnlockAccountRequest"></a>

### UnlockAccountRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base | [AccountOperationRequest](#api-v1-AccountOperationRequest) |  |  |






<a name="api-v1-UnlockAccountResponse"></a>

### UnlockAccountResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_hash | [string](#string) |  |  |





 


<a name="api-v1-Curve"></a>

### Curve


| Name | Number | Description |
| ---- | ------ | ----------- |
| CURVE_UNSPECIFIED | 0 |  |
| CURVE_ECDSA | 1 |  |
| CURVE_EDDSA | 2 |  |


 

 


<a name="api-v1-AccountService"></a>

### AccountService
Service

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| CreateAccount | [CreateAccountRequest](#api-v1-CreateAccountRequest) | [CreateAccountResponse](#api-v1-CreateAccountResponse) |  |
| TransferAccount | [TransferAccountRequest](#api-v1-TransferAccountRequest) | [TransferAccountResponse](#api-v1-TransferAccountResponse) |  |
| DeleteAccount | [DeleteAccountRequest](#api-v1-DeleteAccountRequest) | [DeleteAccountResponse](#api-v1-DeleteAccountResponse) |  |
| UnlockAccount | [UnlockAccountRequest](#api-v1-UnlockAccountRequest) | [UnlockAccountResponse](#api-v1-UnlockAccountResponse) |  |
| ApproveAddress | [ApproveAddressRequest](#api-v1-ApproveAddressRequest) | [ApproveAddressResponse](#api-v1-ApproveAddressResponse) |  |
| RevokeApproval | [RevokeApprovalRequest](#api-v1-RevokeApprovalRequest) | [RevokeApprovalResponse](#api-v1-RevokeApprovalResponse) |  |
| Sign | [SignRequest](#api-v1-SignRequest) | [SignResponse](#api-v1-SignResponse) |  |
| GetAccount | [GetAccountRequest](#api-v1-GetAccountRequest) | [GetAccountResponse](#api-v1-GetAccountResponse) |  |
| IsApproved | [IsApprovedRequest](#api-v1-IsApprovedRequest) | [IsApprovedResponse](#api-v1-IsApprovedResponse) |  |
| IsOwner | [IsOwnerRequest](#api-v1-IsOwnerRequest) | [IsOwnerResponse](#api-v1-IsOwnerResponse) |  |
| IsAccountLocked | [IsAccountLockedRequest](#api-v1-IsAccountLockedRequest) | [IsAccountLockedResponse](#api-v1-IsAccountLockedResponse) |  |

 



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

