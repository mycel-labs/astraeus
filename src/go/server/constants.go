package server

const (
	// ApproveAddress(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)
	APPROVE_ADDRESS_FUNCTION_HASH = "0x16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f"

	// RevokeApproval(SignatureVerifier.TimedSignature timedSignature,string accountId,address _address)
	REVOKE_APPROVAL_FUNCTION_HASH = "0xdb4c3d2d6140b1cf852cff55c9c9a3d0c16d15c9da5e35f87fdc664b1bbf1c32"

	// CreateAccount(SignatureVerifier.TimedSignature timedSignature)
	CREATE_ACCOUNT_FUNCTION_HASH = "0x030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f"

	// TransferAccount(SignatureVerifier.TimedSignature timedSignature,string accountId,address to)
	TRANSFER_ACCOUNT_FUNCTION_HASH = "0x29535a955f68dc291a88a89b6112c958d2edce1684117ccd6b54ca173656f65f"

	// DeleteAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)
	DELETE_ACCOUNT_FUNCTION_HASH = "0x31819315e31d5175ae85114dd27816114c585abc7f9d53ef5ca9bf3c4f2db038"

	// UnlockAccount(SignatureVerifier.TimedSignature timedSignature,string accountId)
	UNLOCK_ACCOUNT_FUNCTION_HASH = "0x062e71868bb32b076e90fa8fa0fa661f47d2f38ee0e9db39a5ab5569589f6332"

	// Sign(SignatureVerifier.TimedSignature timedSignature,string accountId,bytes data)
	SIGN_FUNCTION_HASH = "0xd34780a58dd276dd414ea2abde077f3492ca5422926cdcadf8def7a93f12e993"
)
