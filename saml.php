<?php


require(dirname(__FILE__) . '/xmlseclibs.php');


$file_contents = file_get_contents('saml.b64');

//echo $file_contents;

$samlDecode = base64_decode($file_contents);

//echo $samlDecode;

$uncompressed = gzinflate($samlDecode);

//echo $uncompressed;



/* When we need to locate our own key based on something like a key name */
function locateLocalKey($objKey) {
            $objKey->loadKey(dirname(__FILE__) . "/application-secret.key", TRUE);
}


$doc = new DOMDocument();
$doc->loadXML($uncompressed);





try {
                $objenc = new XMLSecEnc();
                $encData = $objenc->locateEncryptedData($doc);
                if (! $encData) {
                        throw new Exception("Cannot locate Encrypted Data");
                }
                $objenc->setNode($encData);
                $objenc->type = $encData->getAttribute("Type");
                if (! $objKey = $objenc->locateKey()) {
                        throw new Exception("We know the secret key, but not the algorithm");
                }
                $key = NULL;

                if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
                        if ($objKeyInfo->isEncrypted) {
                                $objencKey = $objKeyInfo->encryptedCtx;
                                locateLocalKey($objKeyInfo);
                                $key = $objencKey->decryptKey($objKeyInfo);
                        }
                }
                                                                                                                                                                                          
                if (! $objKey->key && empty($key)) {                                                                                                                                      
                        locateLocalKey($objKey);                                                                                                                                          
                }                                                                                                                                                                         
                if (empty($objKey->key)) {                                                                                                                                                
                        $objKey->loadKey($key);                                                                                                                                           
                }                                                                                                                                                                         
                                                                                                                                                                                          
                $token = NULL;                                                                                                                                                            
                if ($decrypt = $objenc->decryptNode($objKey, TRUE)) {                                                                                                                     
                        $output = NULL;                                                                                                                                                   
                        if ($decrypt instanceof DOMNode) {                                                                                                                                
                                if ($decrypt instanceof DOMDocument) {                                                                                                                    
                                        $output = $decrypt->saveXML();                                                                                                                    
                                } else {                                                                                                                                                  
                                        $output = $decrypt->ownerDocument->saveXML();                                                                                                     
                                }                                                                                                                                                         
                        } else {                                                                                                                                                          
                                $output = $decrypt;                                                                                                                                       
                        }                                            
			echo $output;                                                                                                                      
                }                                                                                                                                                                       
        } catch (Exception $e) {                                                                                                                                                          
                                                                                                                                                                                          
                echo $e;                                                                                                                                                                  
        }                                                                                                                                                                                 
                                                                                                                                                                                          
                                                                                                                                                                                          
                                                                                                                                                                                          
?>             
