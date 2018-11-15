# DecryptHelper
Helper code to decrypt a message encrypted by Rails MessageEncryptor. <br/><br/>
Encryption Call looks like:
```
encryptor = ActiveSupport::MessageEncryptor.new(
            some_secret,
            cipher: 'aes-256-cbc',
            serializer: ActiveSupport::MessageEncryptor::NullSerializer,
          )
encryptor.encrypt_and_sign('Fake Token')
```
<br/><br/>
To try out copy the code from file into a c# environment on `coderpad.io/sandbox`
