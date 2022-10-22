# Web3Signature

Laravel Package for extracting addresses from web3 signed messages

# Usage

In view:

    //prepare message to sign

    const msgtext = {{$msg}};   //Message from backend database sent with view
    const hashedMessage = Web3.utils.fromUtf8(msgtext);
    console.log(hashedMessage);

    //get user to sign the message

    const signature = await window.web3.eth.sign(hashedMessage, accounts[0]);

    //Make request to controller and verify signature in backend via API
    //!!CAUTION!!
    //Not much secure way to do this but only for demo purposes.

    const URL = "api.myproject.com/api/v1/";
    const request = URL + msgtext + "/" + signature;

    window.location.href(request);

In controller:

1: Make a api route in such a way that a signature is passed to controller function
2: Import trait Web3ForContracts into the controller:

        use DeSnake\Web3signature\Web3ForContracts;
        and Include trait into the controller class.
        `` use Web3ForContracts;``

3: Call personal_ecRecover function from controller:

    Note: $msg is plaintext string that is signed and signature is the signed message
        $msg = "Hello World";   //Message from backend database.
        $address = $this->personal_ecRecover($msg, $signature);

# NOTE:

Package is in development mode.

Full examples are available in ./Example folder.

Special Thanks to https://github.com/wmh/php-ecrecover && https://github.com/Wekisen/php-ecrecover && https://github.com/simplito/elliptic-php