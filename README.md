# ses-haskell

The code from an AWS [blog](https://aws.amazon.com/blogs/messaging-and-targeting/ses-and-haskell/) on using Haskell to talk to Simple Email Service (SES).
Since there is no native Haskell SDK, this repo creates a web request, and signs it using the 
[AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html).

I updated the code slightly to work with newer libraries.  There is still some clean up work to do.

example:
``` shell
$ stack exec ses-haskell-exe
Successfully sent with message ID : 0101016fc064f4c4-01044b9a-ffdc-495f-9229-af7e5521602c-000000
```

Nick Brandaleone
nbrand@mac.com

January 2020
