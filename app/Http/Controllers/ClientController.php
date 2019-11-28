<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Key;
use App\Client;
use App\Message;

use Validator;
use ParagonIE\EasyRSA\KeyPair;
use ParagonIE\EasyRSA\EasyRSA;
use ParagonIE\EasyRSA\PublicKey;
use ParagonIE\EasyRSA\PrivateKey;

class ClientController extends Controller
{
    public function generateKey(Request $request)
    {
		// Initialization
    	$items = array();

        // Generate
        $keyPair = KeyPair::generateKeyPair(4096);
        
        $publicKey = $keyPair->getPublicKey();
        $privateKey = $keyPair->getPrivateKey();

        // Get Key
        $getPublicKey = $publicKey->getKey();
        $getPrivateKey = $privateKey->getKey();

        // Clean Line Break
        $getPublicKey = preg_replace( "/\r|\n/", "", $getPublicKey);
        $getPrivateKey = preg_replace( "/\r|\n/", "", $getPrivateKey);

        // Keys
        $items = array(
            'publicKey' => $getPublicKey,
            'privateKey' => $getPrivateKey,
        );

        // Insert to DB
        $insert = new Key;
        $insert->publicKey = $getPublicKey;
        $insert->privateKey = $getPrivateKey;
        $insert->save();

        // Response
        $responses = array(
            'status_code' => 200,
            'status_message' => 'Success',
            'items' => $items,
        );

        // Response JSON
        return response()->json($responses, $responses['status_code']);
    }
    public function register(Request $request)
    {
		// Initialization
    	$items = array();
        $username = $request->username;
        $publicKey = $request->publicKey;

		// Validation Input
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'publicKey' => 'required',
        ]);

        if ($validator->fails())
        {
        	$items = $validator->errors();

	    	$responses = array(
	    		'status_code' => 207,
	    		'status_message' => 'Validation Error',
	    		'errors' => $items,
	    	);
        }

        // Validation Key 
    	$key = Key::where('publicKey', $publicKey)
            ->first();

        if (empty($responses) AND empty($key))
        {
            $responses = array(
                'status_code' => 203,
                'status_message' => 'Public Key - Not Registered',
                'items' => $items,
            );
        }

        // Verification
        if (empty($responses))
        {
            // Key
            $getPublicKey = $key->publicKey;
            $getPrivateKey = $key->privateKey;

            // RSA
            $publicKey = new PublicKey($getPublicKey);
            $privateKey = new PrivateKey($getPrivateKey);

            // Sign
            $usernameSignature = EasyRSA::sign($username, $privateKey);

            // Verify
            if (!EasyRSA::verify($username, $usernameSignature, $publicKey))
            {
                $responses = array(
                    'status_code' => 203,
                    'status_message' => 'Public Key - Invalid',
                    'items' => $items,
                );
            }
        }

        // Success
        if (empty($responses))
        {
            // Encrypt
            $username = EasyRSA::encrypt($username, $publicKey);

            // Client
            session([
                'username' => $username,
                'publicKey' => $getPublicKey,
                'privateKey' => $getPrivateKey,
            ]);

            $items = array(
                'username' => $username,
            );

            // Insert to DB
            $insert = new Client;
            $insert->username = $username;
            $insert->publicKey = $getPublicKey;
            $insert->privateKey = $getPrivateKey;
            $insert->save();
    
            // Response
            $responses = array(
                'status_code' => 200,
                'status_message' => 'Register Success',
                'items' => $items,
            );
        }

        // Response JSON
        return response()->json($responses, $responses['status_code']);
    }
    public function getServerKey(Request $request)
    {
		// Initialization
        $items = array();
        
        // Client
        $publicKey = $request->session()->get('publicKey');

        // Validation Input
        if (empty($publicKey))
        {
            $responses = array(
                'status_code' => 203,
                'status_message' => 'Please Register First',
                'items' => $items,
            );
        }

        // Success
        if (empty($responses))
        {
            $items = array(
                'encryptedSecret' => $publicKey,
            );

            // Response
	    	$responses = array(
	    		'status_code' => 200,
	    		'status_message' => 'Success',
	    		'items' => $items,
            );
        }

        // Response JSON
        return response()->json($responses, $responses['status_code']);
    }
    public function storeSecret(Request $request)
    {
		// Initialization
    	$items = array();
        $username = $request->username;
        $secretName = $request->secretName;
        $encryptedSecret = $request->encryptedSecret;

		// Validation Input
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'secretName' => 'required',
            'encryptedSecret' => 'required',
        ]);

        if ($validator->fails())
        {
        	$items = $validator->errors();

	    	$responses = array(
	    		'status_code' => 207,
	    		'status_message' => 'Validation Error',
	    		'errors' => $items,
	    	);
        }

        // Validation Key 
    	$key = Client::where('publicKey', $encryptedSecret)
            ->first();

        if (empty($responses) AND empty($key))
        {
            $responses = array(
                'status_code' => 203,
                'status_message' => 'Public Key - Not Registered',
                'items' => $items,
            );
        }

        // Verification
        if (empty($responses))
        {
            // Key
            $getPublicKey = $key->publicKey;
            $getPrivateKey = $key->privateKey;

            // RSA
            $publicKey = new PublicKey($getPublicKey);
            $privateKey = new PrivateKey($getPrivateKey);

            // Sign
            $usernameSignature = EasyRSA::sign($username, $privateKey);
            $secretNameSignature = EasyRSA::sign($secretName, $privateKey);

            // Encrypt
            $usernameEncrypt = EasyRSA::encrypt($username, $publicKey);
            $secretNameEncrypt = EasyRSA::encrypt($secretName, $publicKey);

            // Verify
            if (!EasyRSA::verify($username, $usernameSignature, $publicKey))
            {
                $responses = array(
                    'status_code' => 203,
                    'status_message' => 'Public Key - Invalid',
                    'items' => $items,
                );
            }

            // Validation Client 
            if (empty($responses))
            {
                $usernameClient = EasyRSA::decrypt($key->username, $privateKey);
    
                if ($usernameClient != $username)
                {
                    $responses = array(
                        'status_code' => 203,
                        'status_message' => 'Client Not Found',
                        'items' => $items,
                    );
                }
            }
        }

        // Success
        if (empty($responses))
        {
            // Message
            $items = array(
                'username' => $usernameEncrypt,
                'secretName' => $secretNameEncrypt,
            );
            
            // Insert to DB
            $insert = new Message;
            $insert->username = $usernameEncrypt;
            $insert->secretName = $secretNameEncrypt;
            $insert->encryptedSecret = $encryptedSecret;
            $insert->save();

            // Response
	    	$responses = array(
	    		'status_code' => 200,
	    		'status_message' => 'Success',
	    		'items' => $items,
	    	);
        }

        // Response JSON
        return response()->json($responses, $responses['status_code']);
    }
    public function getSecret(Request $request)
    {
		// Initialization
    	$items = array();
        $username = $request->username;
        $secretName = $request->secretName;

        $signatureUsername = $request->signatureUsername;
        $signatureSecretName = $request->signatureSecretName;

        // Clean Space
        $signatureUsername = str_replace(' ', '+', $signatureUsername);
        $signatureSecretName = str_replace(' ', '+', $signatureSecretName);

		// Validation
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'secretName' => 'required',
            'signatureUsername' => 'required',
            'signatureSecretName' => 'required',
        ]);

        if ($validator->fails())
        {
        	$items = $validator->errors();

	    	$responses = array(
	    		'status_code' => 207,
	    		'status_message' => 'Validation Error',
	    		'errors' => $items,
	    	);
        }

        // Key Session
        $getPublicKey = $request->session()->get('publicKey');
        $getPrivateKey = $request->session()->get('privateKey');

        // Validation Session
        if (empty($getPublicKey))
        {
            $responses = array(
                'status_code' => 203,
                'status_message' => 'Please Register First',
                'items' => $items,
            );
        }

        // Validation Client 
        $message = Message::where('username', $signatureUsername)
            ->where('secretName', $signatureSecretName)
            ->first();

        if (empty($responses) AND empty($message))
        {
            $responses = array(
                'status_code' => 203,
                'status_message' => 'Message Not Found',
                'items' => $items,
            );
        }

        // Verification
        if (empty($responses))
        {
            // RSA
            $publicKey = new PublicKey($getPublicKey);
            $privateKey = new PrivateKey($getPrivateKey);

            // Sign
            $usernameSignature = EasyRSA::sign($username, $privateKey);
            $secretNameSignature = EasyRSA::sign($secretName, $privateKey);

            // Verify
            if (!EasyRSA::verify($username, $usernameSignature, $publicKey))
            {
                $responses = array(
                    'status_code' => 203,
                    'status_message' => 'Username Signature Invalid',
                    'items' => $items,
                );
            }
        }

        // Decrypt
        if (empty($responses))
        {
            // Decrypt
            $usernameDecrypt = EasyRSA::decrypt($signatureUsername, $privateKey);
            $secretNameDecrypt = EasyRSA::decrypt($signatureSecretName, $privateKey);

            // Validation Username
            if ($usernameDecrypt != $username)
            {
				$responses = array(
			    	'status_code' => 207,
			    	'status_message' => 'Validation Error',
			    	'errors' => array('username' => ['username and signature data not match']),
			    );
            }
            
            // Validation secretName
            if ($secretNameDecrypt != $secretName)
            {
				$responses = array(
			    	'status_code' => 207,
			    	'status_message' => 'Validation Error',
			    	'errors' => array('secretName' => ['secretName and signature data not match']),
			    );
            }
        }

        // Success
        if (empty($responses))
        {
            // Decrypt
            $usernameDecrypt = EasyRSA::decrypt($signatureUsername, $privateKey);
            $secretNameDecrypt = EasyRSA::decrypt($signatureSecretName, $privateKey);

            // Message
            $items = array([
                'username' => $usernameDecrypt,
                'secretName' => $secretNameDecrypt,
            ]);

            // Response
            $responses = array(
                'status_code' => 200,
                'status_message' => 'Success',
                'items' => $items,
            );
        }

        // Response JSON
        return response()->json($responses, $responses['status_code']);
    }
}
