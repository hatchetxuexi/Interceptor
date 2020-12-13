
function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA)
			{
				$CAsubject = $certSubject
				$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
				$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
				#Issuer Property for cleanup
				$issuer = "__Interceptor_Trusted_Root"
				$issuerdn = new-object -com "X509Enrollment.CX500DistinguishedName"
				$issuerdn.Encode("CN=" + $issuer, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
				#Subject Alternative Name
				$objRfc822Name = new-object -com "X509Enrollment.CAlternativeName";
				$objAlternativeNames = new-object -com "X509Enrollment.CAlternativeNames";
				$objExtensionAlternativeNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames";
				
				#Set Alternative RFC822 Name 
				$objRfc822Name.InitializeFromString(3, $certSubject); #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374830(v=vs.85).aspx
				
				#Set Alternative Names 
				$objAlternativeNames.Add($objRfc822Name);
				$objExtensionAlternativeNames.InitializeEncode($objAlternativeNames);
				
				# Create a new Private Key
				$key = new-object -com "X509Enrollment.CX509PrivateKey"
				$key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider" #"Microsoft Enhanced Cryptographic Provider v1.0"
				$key.ExportPolicy = 2; #Mark As Exportable
				
				# Set CAcert to 1 to be used for Signature
				if($isCA)
					{
						$key.KeySpec = 2 
					}
				else
					{
						$key.KeySpec = 1
					}
				$key.Length = 1024
				$key.MachineContext = $false # 1 For Machine 0 For User
				$key.Create() 
				
				
				 
				# Create Attributes
				$serverauthoid = new-object -com "X509Enrollment.CObjectId"
				$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
				$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
				$ekuoids.add($serverauthoid)
				$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
				$ekuext.InitializeEncode($ekuoids)

				$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
				$cert.InitializeFromPrivateKey(1, $key, "")
				$cert.Subject = $dn
				$cert.Issuer = $issuerdn
				$cert.NotBefore = (get-date).AddDays(-1) #Backup One day to Avoid Timing Issues
				$cert.NotAfter = $cert.NotBefore.AddDays(90) #Arbitrary... Change to persist longer...
				#Use Sha256
				$hashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
				$hashAlgorithmObject.InitializeFromAlgorithmName(1,0,0,"SHA256")
				$cert.HashAlgorithm = $hashAlgorithmObject
				#Good Reference Here http://www.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell/
				
				$cert.X509Extensions.Add($ekuext)
				$cert.X509Extensions.Add($objExtensionAlternativeNames);
				if ($isCA)
				{
					$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
					$basicConst.InitializeEncode("true", 1)
					$cert.X509Extensions.Add($basicConst)
				}
				else
				{              
					$signer = (Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
					$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
					$signerCertificate.Initialize(0,0,4, $signer.Thumbprint)
					$cert.SignerCertificate = $signerCertificate
				}
				$cert.Encode()

				$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
				$enrollment.InitializeFromRequest($cert)
				$certdata = $enrollment.CreateRequest(0)
				$enrollment.InstallResponse(2, $certdata, 0, "")

				if($isCA)
				{              
												
					# Need a Better way to do this...
					$CACertificate = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
					# Install CA Root Certificate
					$StoreScope = "CurrentUser"
					$StoreName = "Root"
					$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
					$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
					$store.Add($CACertificate)
					$store.Close()
												
				}
				else
				{
					return (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match $CAsubject })
				} 
				 
			}




$Global:Listener = [HashTable]::Synchronized(@{})
$Global:CnQueue = [System.Collections.Queue]::Synchronized((New-Object System.collections.queue))
$Global:space = [RunSpaceFactory]::CreateRunspace()
$space.Open()
$space.SessionStateProxy.setVariable("CnQueue", $CnQueue)
$space.SessionStateProxy.setVariable("Listener", $Listener)
$Global:newPowerShell = [PowerShell]::Create()
$newPowerShell.Runspace = $space
$Timer = New-Object Timers.Timer
$Timer.Enabled = $true
$Timer.Interval = 1000
Register-ObjectEvent -SourceIdentifier MonitorClientConnection -InputObject $Timer -EventName Elapsed -Action {
    While($CnQueue.count -ne 0) {
        $client = $CnQueue.Dequeue()
        $newRunspace = [RunSpaceFactory]::CreateRunspace()
        $newRunspace.Open()
        $newRunspace.SessionStateProxy.setVariable("client", $client)
        $newPowerShell = [PowerShell]::Create()
        $newPowerShell.Runspace = $newRunspace
		
        $process = {
		
			#-------------------------------------------------------------------------
			# This script block is executed in a separate PowerShell object, as another
			#
			
			
			#----------------------------------------------------------------------------------------------------
			# Certificate Helpers
			
			function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA)
			{
				$CAsubject = $certSubject
				$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
				$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
				#Issuer Property for cleanup
				$issuer = "__Interceptor_Trusted_Root"
				$issuerdn = new-object -com "X509Enrollment.CX500DistinguishedName"
				$issuerdn.Encode("CN=" + $issuer, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
				#Subject Alternative Name
				$objRfc822Name = new-object -com "X509Enrollment.CAlternativeName";
				$objAlternativeNames = new-object -com "X509Enrollment.CAlternativeNames";
				$objExtensionAlternativeNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames";
				
				#Set Alternative RFC822 Name 
				$objRfc822Name.InitializeFromString(3, $certSubject); #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374830(v=vs.85).aspx
				
				#Set Alternative Names 
				$objAlternativeNames.Add($objRfc822Name);
				$objExtensionAlternativeNames.InitializeEncode($objAlternativeNames);
				
				# Create a new Private Key
				$key = new-object -com "X509Enrollment.CX509PrivateKey"
				$key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider" #"Microsoft Enhanced Cryptographic Provider v1.0"
				$key.ExportPolicy = 2; #Mark As Exportable
				
				# Set CAcert to 1 to be used for Signature
				if($isCA)
					{
						$key.KeySpec = 2 
					}
				else
					{
						$key.KeySpec = 1
					}
				$key.Length = 1024
				$key.MachineContext = $false # 1 For Machine 0 For User
				$key.Create() 
				
				
				 
				# Create Attributes
				$serverauthoid = new-object -com "X509Enrollment.CObjectId"
				$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
				$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
				$ekuoids.add($serverauthoid)
				$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
				$ekuext.InitializeEncode($ekuoids)

				$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
				$cert.InitializeFromPrivateKey(1, $key, "")
				$cert.Subject = $dn
				$cert.Issuer = $issuerdn
				$cert.NotBefore = (get-date).AddDays(-1) #Backup One day to Avoid Timing Issues
				$cert.NotAfter = $cert.NotBefore.AddDays(90) #Arbitrary... Change to persist longer...
				#Use Sha256
				$hashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
				$hashAlgorithmObject.InitializeFromAlgorithmName(1,0,0,"SHA256")
				$cert.HashAlgorithm = $hashAlgorithmObject
				#Good Reference Here http://www.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell/
				
				$cert.X509Extensions.Add($ekuext)
				$cert.X509Extensions.Add($objExtensionAlternativeNames);
				if ($isCA)
				{
					$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
					$basicConst.InitializeEncode("true", 1)
					$cert.X509Extensions.Add($basicConst)
				}
				else
				{              
					$signer = (Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
					$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
					$signerCertificate.Initialize(0,0,4, $signer.Thumbprint)
					$cert.SignerCertificate = $signerCertificate
				}
				$cert.Encode()

				$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
				$enrollment.InitializeFromRequest($cert)
				$certdata = $enrollment.CreateRequest(0)
				$enrollment.InstallResponse(2, $certdata, 0, "")

				if($isCA)
				{              
												
					# Need a Better way to do this...
					$CACertificate = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
					# Install CA Root Certificate
					$StoreScope = "CurrentUser"
					$StoreName = "Root"
					$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
					$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
					$store.Add($CACertificate)
					$store.Close()
												
				}
				else
				{
					return (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match $CAsubject })
				} 
				 
			}


			function Receive-ServerHttpResponse ([System.Net.WebResponse] $response)
			{
				#Returns a Byte[] from HTTPWebRequest, also for HttpWebRequest Exception Handling
				Try
				{
					[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
					[int]$rawStatusCode = [int]$response.StatusCode
					[string]$rawStatusDescription = [string]$response.StatusDescription
					$rawHeadersString = New-Object System.Text.StringBuilder 
					$rawHeaderCollection = $response.Headers
					$rawHeaders = $response.Headers.AllKeys
					[bool] $transferEncoding = $false 
					# This is used for Chunked Processing.
					
					foreach($s in $rawHeaders)
					{
						 #We'll handle setting cookies later
						if($s -eq "Set-Cookie") { Continue }
						if($s -eq "Transfer-Encoding") 
						{
							$transferEncoding = $true
							continue
						}
						[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string stuff.
					}	
					$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))' #Split on "," but not ", "
					if($setCookieString)
					{
						foreach ($respCookie in $setCookieString)
						{
							if($respCookie -eq "," -Or $respCookie -eq "") {continue}
							[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie) 
						}
					}
					
					$responseStream = $response.GetResponseStream()
					
					$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
					
					[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
					
					Write-Host $rstring 
					
					[void][byte[]] $outdata 
					$tempMemStream = New-Object System.IO.MemoryStream
					[byte[]] $respbuffer = New-Object Byte[] 32768 # 32768
					
					if($transferEncoding)
					{
						$reader = New-Object System.IO.StreamReader($responseStream)
						[string] $responseFromServer = $reader.ReadToEnd()
						
						if ($Tamper)
						{
							if($responseFromServer -match 'Cyber')
							{
								$responseFromServer = $responseFromServer -replace 'Cyber', 'Kitten'
							}
						}
						
						$outdata = [System.Text.Encoding]::UTF8.GetBytes($responseFromServer)
						$reader.Close()
					}
					else
					{
						while($true)
						{
							[int] $read = $responseStream.Read($respbuffer, 0, $respbuffer.Length)
							if($read -le 0)
							{
								$outdata = $tempMemStream.ToArray()
								break
							}
							$tempMemStream.Write($respbuffer, 0, $read)
						}
					
						if ($Tamper -And $response.ContentType -match "text/html")
						{
							
							$outdataReplace = [System.Text.Encoding]::UTF8.GetString($outdata)
							if($outdataReplace -match 'Cyber')
							{
								$outdataReplace = $outdataReplace -Replace 'Cyber', 'Kitten' 
								$outdata = [System.Text.Encoding]::UTF8.GetBytes($outdataReplace)
							}
							
							
						}
					}
					[byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
					#Combine Header Bytes and Entity Bytes 
					
					[System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
					[System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length ) 
				
					
					$tempMemStream.Close()
					$response.Close()
					
					return $rv
				}
				Catch [System.Exception]
				{
					[Console]::WriteLine("Get Response Error")
					[Console]::WriteLine($_.Exception.Message)
				}#End Catch
				
			}

			function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy )
			{	
				#Prepare and Send an HttpWebRequest From Byte[] Returns Byte[]
				Try
				{
					$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
					[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
					
					[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
					[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
					
					$request.KeepAlive = $false
					$request.ProtocolVersion = [System.Net.Httpversion]::version11 
					$request.ServicePoint.ConnectionLimit = 1
					if($proxy -eq $null) { $request.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
					else { $request.Proxy = $proxy }
					$request.Method = $httpMethod
					$request.AllowAutoRedirect = $false 
					$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
				
					For ($i = 1; $i -le $requestString.Length; $i++)
					{
						$line = $requestString[$i] -split ": " 
						if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
						Try
						{
							#Add Header Properties Defined By Class
							switch($line[0])
							{
								"Accept" { $request.Accept = $line[1] }
								"Connection" { "" }
								"Content-Length" { $request.ContentLength = $line[1] }
								"Content-Type" { $request.ContentType = $line[1] }
								"Expect" { $request.Expect = $line[1] }
								"Date" { $request.Date = $line[1] }
								"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
								"Range" { $request.Range = $line[1] }
								"Referer" { $request.Referer = $line[1] }
								"User-Agent" { $request.UserAgent = $line[1] } 
								# Added Tampering Here...User-Agent Example
								"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
								default {
											if($line[0] -eq "Accept-Encoding")
											{	
												$request.Headers.Add( $line[0], " ") #Take that Gzip...
												#Otherwise have to decompress response to tamper with content...
											}
											else
											{
												$request.Headers.Add( $line[0], $line[1])
											}	
				
										}
							}
							
						}
						Catch
						{
							
						}
					}
						
					if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0)) 
					{
						[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
						$outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
						$outputStream.Close()
					}
					
					
					return Receive-ServerHttpResponse $request.GetResponse()
					
				}
				Catch [System.Net.WebException]
				{
					#HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
					if ($_.Exception.Response) 
					{
						return Receive-ServerHttpResponse $_.Exception.Response
					}
						
				}#End Catch Web Exception
				Catch [System.Exception]
				{	
					Write-Verbose $_.Exception.Message
				}#End General Exception Occured...
				
			}#Proxied Get

			function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
			{
				
				Try
				{	
					$clientStream = $client.GetStream()
					$byteArray = new-object System.Byte[] 1024 
					[void][byte[]] $byteClientRequest


					do 
					 {
						[int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) 
						$byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  
					 
					 } While ($clientStream.DataAvailable -And $NumBytesRead -gt 0) 
						
					#Now you have a byte[] Get a string...  Caution, not all that is sent is "string" Headers will be.
					$requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
					
					[string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
					[string[]] $methodParse = $requestArray[0] -split " "
					#Begin SSL MITM IF Request Contains CONNECT METHOD
					
					if($methodParse[0] -ceq "CONNECT")
					{
						[string[]] $domainParse = $methodParse[1].Split(":")
						
						$CertSubjectName = $domainParse[0]
						[console]::WriteLine("****$CertSubjectName*******`n")
						
						$connectSpoof = [System.Text.Encoding]::Ascii.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + [System.DateTime]::Now.ToString() + "`r`n`r`n")
						$clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
						$clientStream.Flush()
						$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
						$sslStream.ReadTimeout = 500
						$sslStream.WriteTimeout = 500
						#Duplicate Certifccates.
						$sslcertfake = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=" + $CertSubjectName })
						
						
						
						if ($sslcertfake -eq $null)
						{
							[console]::WriteLine("**** Cert Created For $CertSubjectName *******`n")
							$sslcertfake = Invoke-CreateCertificate $CertSubjectName $false
						}
						else
						{
							$sslcertfake = $sslcertfake[0]
						}
						
					
						$sslStream.AuthenticateAsServer($sslcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
					
						$sslbyteArray = new-object System.Byte[] 32768
						[void][byte[]] $sslbyteClientRequest
						
						do 
						 {
							[int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) 
							$sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  
						 } while ( $clientStream.DataAvailable  )
						
						$SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
						[Console]::WriteLine($SSLRequest) 
						 
						"TimeStamp $((Get-Date).ToUniversalTime().ToString('yyMMddTHHmmss')) `n" + $SSLRequest | Add-Content C:\Users\Mobile\Documents\InterceptorLog.txt 
						
						
						[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
						[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
						
						$secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
						
						[byte[]] $byteResponse =  Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy
						
						if($byteResponse[0] -eq '0x00')
						{
							$sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
						}
						else
						{
							$sslStream.Write($byteResponse, 0, $byteResponse.Length )
						}
						
						
						
					}#End CONNECT/SSL Processing
					Else
					{
						[console]::WriteLine($requestString)
						$requestString | Add-Content C:\Users\Mobile\Documents\InterceptorLog.txt 
						
						[byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy
						if($proxiedResponse[0] -eq '0x00')
						{
							$clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1 )	
						}
						else
						{
							$clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length )	
						}
						
					}#End Http Proxy
					
					
				}# End HTTPProcessing Block
				Catch
				{
					Write-Verbose $_.Exception.Message
					$client.Close()
				}
				Finally
				{
					$client.Close()
				}
							
			}
			
			
			#-------------------------------------------------------------------------
			

			$proxy = $null
			if($client -ne $null)
			{
				Receive-ClientHttpRequest $client $proxy
			}
			
			
        }
        $jobHandle = $newPowerShell.AddScript($process).BeginInvoke()
        #jobHandle you need to save for future to cleanup
    }
}
$listener = {
    $Listener['listener'] = New-Object System.Net.Sockets.TcpListener("127.0.0.1", "8000")
	$Listener.SetSocketOption([System.Net.SocketOptionLeve]::Socket, [System.Net.SocketOptionName]::ReuseAddress, $true);
    $Listener['listener'].Start()
    [console]::WriteLine("Listening on :8000")
    while ($true) {
        $c = $Listener['listener'].AcceptTcpClient()
        If($c -ne $Null) {
            [console]::WriteLine("{0} >> Accepted Client " -f (Get - Date).ToString())
            $CnQueue.Enqueue($c)
        }
        Else {
            [console]::WriteLine("Shutting down")
            Break
        }
    }
}


# Create And Install Trusted Root CA.
# Create Log File 

"$(Get-Date) `n" | Out-File C:\Users\Mobile\Documents\InterceptorLog.txt

$CACertificateCheck = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" }) 
						
							
if ($CACertificateCheck -eq $null)
{
[console]::WriteLine("**** Cert Created For $CertSubjectName *******`n")
Invoke-CreateCertificate "__Interceptor_Trusted_Root" $true
}
else
{
	[console]::WriteLine("**** CA Certificate Present *******`n")
}

$Timer.Start()
$Global:handle = $newPowerShell.AddScript($listener).BeginInvoke()
