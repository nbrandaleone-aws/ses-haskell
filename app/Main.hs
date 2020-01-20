{-# Language OverloadedStrings #-}
module Main where

-- import Lib
import Control.Applicative
import Control.Monad
import Crypto.Hash (Digest, SHA256, hmac, hmacGetDigest, hash, digestToHexByteString)
import Data.Byteable (toBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16 (encode)
import qualified Data.ByteString.Char8 as C
import Data.CaseInsensitive (original)
import Data.Char (toLower)
import Data.Text (Text, unpack)
import Data.Time (getCurrentTime)
import Data.Time.Format (formatTime, FormatTime, TimeLocale, parseTimeM, parseTimeOrError, defaultTimeLocale)
import Data.Time.Clock (UTCTime)
import Data.List (intersperse, lines, sortBy)
import Data.Monoid ((<>))
import Network.HTTP.Conduit
import Network.HTTP.Types
import Network.HTTP.Types.Header
import System.Environment (getEnv)

import Blaze.ByteString.Builder (toByteString)
import Data.Aeson

import Data.List (sortBy)


canonicalRequest :: Request -> ByteString -> ByteString
canonicalRequest req body = C.concat $
    intersperse "\n"
        [ method req
        , path req
        , queryString req
        , canonicalHeaders req
        , signedHeaders req
        , hexHash body
        ]
hexHash :: ByteString -> ByteString
hexHash p = digestToHexByteString (hash p :: Digest SHA256)

headers :: Request -> [Header]
headers req = sortBy (\(a,_) (b,_) -> compare a b) (("host", host req) : requestHeaders req)

canonicalHeaders :: Request -> ByteString
canonicalHeaders req =
    C.concat $ map (\(hn,hv) -> bsToLower (original hn) <> ":" <> hv <> "\n") hs
  where hs = headers req

bsToLower :: ByteString -> ByteString
bsToLower = C.map toLower

signedHeaders :: Request -> ByteString
signedHeaders req =
    C.concat . intersperse ";"  $ map (\(hn,_) -> bsToLower (original hn)) hs
  where hs = headers req

v4DerivedKey :: ByteString -> -- ^ AWS Secret Access Key
                ByteString -> -- ^ Date in YYYYMMDD format
                ByteString -> -- ^ AWS region
                ByteString -> -- ^ AWS service
                ByteString
v4DerivedKey secretAccessKey date region service = hmacSHA256 kService "aws4_request"
  where kDate = hmacSHA256 ("AWS4" <> secretAccessKey) date
        kRegion = hmacSHA256 kDate region
        kService = hmacSHA256 kRegion service

hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 key p = toBytes $ (hmacGetDigest $ hmac key p :: Digest SHA256)

stringToSign :: UTCTime    -> -- ^ current time
                ByteString -> -- ^ The AWS region
                ByteString -> -- ^ The AWS service
                ByteString -> -- ^ Hashed canonical request
                ByteString
stringToSign date region service hashConReq = C.concat
    [ "AWS4-HMAC-SHA256\n"
    , C.pack (formatAmzDate date) , "\n"
    , C.pack (format date) , "/"
    , region , "/"
    , service
    , "/aws4_request\n"
    , hashConReq
    ]

format :: UTCTime -> String
format = formatTime defaultTimeLocale "%Y%m%d"

formatAmzDate :: UTCTime -> String
formatAmzDate = formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

createSignature ::  Request         -> -- ^ Http request
                    ByteString      -> -- ^ Body of the request
                    UTCTime         -> -- ^ Current time
                    ByteString      -> -- ^ Secret Access Key
                    ByteString      -> -- ^ AWS region
                    ByteString
createSignature req body now key region = v4Signature dKey toSign
  where canReqHash = hexHash $ canonicalRequest req body
        toSign = stringToSign now region "ses" canReqHash
        dKey = v4DerivedKey key (C.pack $ format now) region "ses"

v4Signature :: ByteString -> ByteString -> ByteString
v4Signature derivedKey payLoad = B16.encode $ hmacSHA256 derivedKey payLoad

-- SES SendEmailCall
data SendEmailRequest = SendEmailRequest
    { region            :: ByteString
    , accessKeyId       :: ByteString
    , secretAccessKey   :: ByteString
    , source            :: ByteString
    , to                :: [ByteString]
    , subject           :: ByteString
    , body              :: ByteString
    } deriving Show

usEast1 :: ByteString
usEast1 = "us-east-1"

usWest2 :: ByteString
usWest2 = "us-west-2"

euWest1 :: ByteString
euWest1 = "eu-west-1"

sendEmail :: SendEmailRequest -> IO (Either String SendEmailResponse)
sendEmail sendReq = do
    fReq <- parseUrl $ "https://email." ++ C.unpack (region sendReq) ++ ".amazonaws.com"
    now <- getCurrentTime
    let req = fReq
                { requestHeaders =
                    [ ("Accept", "text/json")
                    , ("Content-Type", "application/x-www-form-urlencoded")
                    , ("x-amz-date", C.pack $ formatAmzDate now)
                    ]
                , method = "POST"
                , requestBody = RequestBodyBS reqBody
                }
        sig = createSignature req reqBody now (secretAccessKey sendReq) (region sendReq)
    manager <- newManager tlsManagerSettings
    resp <- httpLbs (authenticateRequest sendReq now req reqBody) manager
    case responseStatus resp of
        (Status 200 _) -> return $ eitherDecode (responseBody resp)
        (Status code msg) ->
            return $ Left ("Request failed with status code <" ++
                show code ++ "> and message <" ++ C.unpack msg ++ ">")
  where
    reqBody = renderSimpleQuery False $
                    [ ("Action", "SendEmail")
                    , ("Source", source sendReq)
                    ] ++ toAddressQuery (to sendReq) ++
                    [ ("Message.Subject.Data", subject sendReq)
                    , ("Message.Body.Text.Data", body sendReq)
                    ]

authenticateRequest :: SendEmailRequest -> UTCTime -> Request -> ByteString -> Request
authenticateRequest sendReq now req body =
    req { requestHeaders =
            authHeader now (accessKeyId sendReq)
                           (signedHeaders req) sig
                           (region sendReq) :
                           (requestHeaders req)
        }
  where sig = createSignature req body now (secretAccessKey sendReq) (region sendReq)

toAddressQuery :: [ByteString] -> SimpleQuery
toAddressQuery tos =
    zipWith (\index address ->
                ( "Destination.ToAddresses.member." <>
                    C.pack (show index)
                , address)
            ) [1..] tos

authHeader ::   UTCTime     -> -- ^ Current time
                ByteString  -> -- ^ Secret access key
                ByteString  -> -- ^ Signed headers
                ByteString  -> -- ^ Signature
                ByteString  -> -- ^ AWS Region
                Header
authHeader now sId signHeads sig region =
    ( "Authorization"
    , C.concat
        [ "AWS4-HMAC-SHA256 Credential="
        , sId , "/"
        , C.pack (format now) , "/"
        , region
        , "/ses/aws4_request, SignedHeaders="
        , signHeads
        , ", Signature="
        , sig
        ]
    )

data SendEmailResponse = SendEmailResponse
    { requestId     :: Text
    , messageId     :: Text
    } deriving Show

instance FromJSON SendEmailResponse where
    parseJSON (Object o) = do
        response <- o .: "SendEmailResponse"
        reqId <- response .: "ResponseMetadata" >>= (.: "RequestId")
        msgId <- response .: "SendEmailResult" >>= (.: "MessageId")
        return $ SendEmailResponse reqId msgId
    parseJSON _ = mzero

main :: IO ()
main = do
    awsId <- C.pack <$> getEnv "AWS_ACCESS_KEY_ID"
    awsSecret <- C.pack <$> getEnv "AWS_SECRET_ACCESS_KEY"
    let sendRequest = SendEmailRequest usWest2 awsId awsSecret "nbrand@mac.com"
                        ["nbrand@mac.com"] "Sent from Haskell"
                        "This email was sent through SES using Haskell!"
    response <- sendEmail sendRequest
    case response of
        Left err -> putStrLn $ "Failed to send : " ++ err
        Right resp ->
            putStrLn $ "Successfully sent with message ID : " ++ unpack (messageId resp)

