local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local io = require "io"
local have_openssl, openssl = pcall(require, "openssl")

description = [[

Retrieves a server's SSL certificate and detects if the server is using an X509 
certificate whose SubjectName or IssuerName are part of  a list of suspicious names 
or IPs, it is a self-signed certificate, or the IP associated with the web server 
name does not belong to the range of IPs associated with such domain.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Not valid before: 2011-03-23 00:00:00
|_Not valid after:  2013-04-01 23:59:59
</code>

...
]]

---
-- @see ssl-cert-intaddr.nse
--
-- @output
-- 443/tcp open  https
-- | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
-- /stateOrProvinceName=California/countryName=US
-- | Not valid before: 2011-03-23 00:00:00
-- |_Not valid after:  2013-04-01 23:59:59
--
-- @args list the path to the file with the blacklist. (default: blacklist.csv)
-- 
--- Optional arguments
-- list: path to the file with the blacklist (blacklist.csv)
-- dns-file: path to the file with the DNS records (dns.csv)

-- @usage nmap -sV <target-ip> --script=./untrustedX509certs.nse
-- @usage nmap -sV <target-ip> --script=./untrustedX509certs.nse --script-args list=blacklistfile.csv
-- @usage nmap -sV <target-ip> --script=./untrustedX509certs.nse --script-args dns-file=dnsfile.csv
-- @usage nmap -sV <target-ip> --script=./untrustedX509certs.nse --script-args list=blacklistfile.csv dns-file=dnsfile.csv
--
---
-- @xmloutput
-- <table key="subject">
--   <elem key="1.3.6.1.4.1.311.60.2.1.2">Delaware</elem>
--   <elem key="1.3.6.1.4.1.311.60.2.1.3">US</elem>
--   <elem key="postalCode">95131-2021</elem>
--   <elem key="localityName">San Jose</elem>
--   <elem key="serialNumber">3014267</elem>
--   <elem key="countryName">US</elem>
--   <elem key="stateOrProvinceName">California</elem>
--   <elem key="streetAddress">2211 N 1st St</elem>
--   <elem key="organizationalUnitName">PayPal Production</elem>
--   <elem key="commonName">www.paypal.com</elem>
--   <elem key="organizationName">PayPal, Inc.</elem>
--   <elem key="businessCategory">Private Organization</elem>
-- </table>
-- <table key="issuer">
--   <elem key="organizationalUnitName">Terms of use at https://www.verisign.com/rpa (c)06</elem>blacklistFile
--   <elem key="organizationName">VeriSign, Inc.</elem>
--   <elem key="commonName">VeriSign Class 3 Extended Validation SSL CA</elem>
--   <elem key="countryName">US</elem>
-- </table>
-- <table key="pubkey">
--   <elem key="type">rsa</elem>
--   <elem key="bits">2048</elem>
--   <elem key="modulus">DF40CCF2C50A0D65....35B5927DF25D4DE5</elem>
--   <elem key="exponent">65537</elem>
-- </table>
-- <elem key="sig_algo">sha1WithRSAEncryption</elem>
-- <table key="validity">
--   <elem key="notBefore">2011-03-23T00:00:00+00:00</elem>
--   <elem key="notAfter">2013-04-01T23:59:59+00:00</elem>
-- </table>
-- <elem key="md5">bf47cecad861efa77d1488ad4a73cb5b</elem>
-- <elem key="sha1">d8465221467a0d153df09f2eaf6d439002139a68</elem>
-- <elem key="pem">-----BEGIN CERTIFICATE-----
-- MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
-- ...
-- 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
-- -----END CERTIFICATE-----
-- </elem>

author = "Javier Sande"
author = "Tristán Vaquero"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

local blacklistFile = stdnse.get_script_args('list') or 'blacklist.csv'
local dnsPath = stdnse.get_script_args('dns-file') or 'dns.csv'

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-------------------------------------------------------------------------------
-- Global variables
-------------------------------------------------------------------------------

-- Table to store the blacklist
local issuerBlacklist = {}
local signatureBlacklist = {}
local loadedBlackList = false

-- Table to store the dns records
local dnsRecords = {}
local loadedDNS= false

-- Variables to store the CA certificate
local verify_authenticity = false
local verify_issuance = false

-------------------------------------------------------------------------------
-- ENUM definitions
-------------------------------------------------------------------------------

CertValidity = {
  NOT_YET_VALID = 1,
  EXPIRED = 2,
  VALID = 3,
  SHORT_VALIDITY = 4
}

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { 
  "commonName",
  "organizationName",
  "stateOrProvinceName",
  "countryName"
}

-------------------------------------------------------------------------------
-- Report definition
-------------------------------------------------------------------------------

local securityReport = {}
securityReport.is_blacklisted = false
securityReport.ca_is_blacklisted = false
securityReport.warnings = {}

-------------------------------------------------------------------------------
-- Parsermethods for Punycode/IDN Homograph Attack detection
-- Obtained from: https://community.netwitness.com/t5/netwitness-community-blog/
-- lua-parser-for-punycode-idn-homograph-attack/ba-p/517951
-------------------------------------------------------------------------------

local blacklist = {
  0x251,  -- ɑ
  0x3b1,  -- α
  0x430,  -- а
  0x42c,  -- Ь
  0x3f2,  -- ϲ
  0x441,  -- с
  0x217d, -- ⅽ
  0x501,  -- ԁ
  0x217e, -- ⅾ
  0x435,  -- е
  0x261,  -- ɡ
  0x4bb,  -- һ
  0x456,  -- і
  0x13a5, -- Ꭵ
  0x2170, -- ⅰ 
  0x3f3,  -- ϳ
  0x458,  -- ј
  0x575,  -- յ
  0x39a,  -- Κ
  0x217c, -- ⅼ
  0x217f, -- ⅿ
  0x4cf,  -- ӏ
  0x3bf,  -- ο
  0x43e,  -- о
  0x1d0f, -- ᴏ
  0x3c1,  -- ρ
  0x440,  -- р
  0x455,  -- ѕ
  0x3c5,  -- υ
  0x475,  -- ѵ
  0x2174, -- ⅴ
  0x461,  -- ѡ
  0x1d21, -- ᴡ
  0x445,  -- х
  0x2179, -- ⅹ
  0x3b3,  -- γ
  0x443,  -- у
}

local blacklistSet = {}
for i, c in ipairs(blacklist) do
  blacklistSet[c] = true
end

-- Parameter values for Punycode: https://tools.ietf.org/html/rfc3492#section-5
local base = 36
local tmin = 1
local tmax = 26
local skew = 38
local damp = 700
local initial_bias = 72
local initial_n = 128

-- Bias Adaptation: https://tools.ietf.org/html/rfc3492#section-6.1
local adapt = function(delta, numPoints, firstTime)
  delta = firstTime and math.floor( delta / damp ) or math.floor( delta / 2 )
  
  delta = delta + math.floor( delta / numPoints )
  
  local k = 0
  
  while delta > math.floor(( base - tmin ) * tmax / 2) do
    delta = math.floor( delta / ( base - tmin) )
    k = k + 1
  end
  
	return base * k + math.floor((base - tmin + 1) * delta / (delta + skew));
end

-- https://github.com/HalosGhost/lua-punycode/blob/master/src/punycode.lua
local charToDigit = function (character)
  local c = string.byte(character)
  
  local a = (c >= 65 and c <= 90) and c - 65 or
        (c >= 97 and c <= 122) and c - 97 or
        (c >= 48 and c <= 57) and c - 22 or c

  return a
end

-- Decoding Procedure: https://tools.ietf.org/html/rfc3492#section-6.2
local getUnicodeCodepoints = function (host)
  local codepoints = { }
  
  if string.sub(host, 1, 4) ~= "xn--" then
    return { }
  end
  
  host = string.sub(host, 5)
  
  local last_delim = string.find(host, "-[^-]*$")
  
  local n = initial_n
  local i = 0
  local bias = initial_bias
  local output = last_delim and string.sub(host, 0, last_delim - 1) or ""
  local extended = last_delim and string.sub(host, last_delim + 1) or host
  
  while string.len(extended) > 0 do
    local oldi = i
    local w = 1
    for k = base, math.huge, base do
      local digit = charToDigit(string.sub(extended,1,1))
      extended = string.sub(extended, 2)
      
      i = i + digit * w
      local t = (k <= bias) and tmin or
                (k >= bias + tmax) and tmax or
                (k - bias)
      if digit < t then
        break
      end
      w = w * (base - t)
    end
    bias = adapt(i - oldi, string.len(output) + 1, oldi == 0)
    n = n + math.floor( i / (string.len(output) + 1) )
    i = i % (string.len(output) + 1)
    codepoints[#codepoints + 1] = n
    output = string.sub(output,1,i) .. " " .. string.sub(output,i+1)
    i = i + 1
  end
  
  return codepoints
  --return output
end

local function check(host)
  local blacklistHit = 0
  local unicodeCount = 0
  
  for domain in string.gmatch(host, "[^.]+") do
    local out = getUnicodeCodepoints(domain)
    unicodeCount = unicodeCount + #out
    
    for k, v in ipairs(out) do
      
      if blacklistSet[v] then
        blacklistHit = blacklistHit + 1
      end
    end
  end
 
  return unicodeCount > 0 and blacklistHit > 0 and blacklistHit/unicodeCount >= 0.75
end

-------------------------------------------------------------------------------
-- UTIL functions
-------------------------------------------------------------------------------

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

-- Extract alternative names from a certificate
local function extract_alternative_names(cert)
  local altNames = {}
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      if ext.name == "X509v3 Subject Alternative Name" then
        table.insert(altNames, ext.value)
      end
    end
  end

  return altNames
end

-- Load the dns records from a file
local function load_dns(file)
  local file_handle = io.open(file, "r")
  if not file_handle then
    return false
  end

  for line in file_handle:lines() do
    local domaninName, ipRange = line:match("([^;]+);([^;]+))")
    if domaninName and ipRange then
     local min, max = ipRange:match("([^-]+)-([^-]+))")
      dnsRecords[domaninName] = {
        min = min,
        max = max
      }
    end
  end

  file_handle:close()
  return true
end

-- Load the blacklist from a file
local function load_blacklist(file)
  local file_handle = io.open(file, "r")
  if not file_handle then
    return false
  end

  for line in file_handle:lines() do
    local date, issuer, severity, fingerprint = line:match("([^;]+);([^;]+);([^;]+);([^;]+)")
    if date and issuer and severity then
      issuerBlacklist[issuer] = {
        severity = severity,
        inclusion_date = date
      }
      signatureBlacklist[fingerprint] = {
        severity = severity,
        inclusion_date = date
      }
    end
  end

  file_handle:close()
  return true
end

local function compare_subject_issuer(subject, issuer)

  if subject.commonName ~= issuer.commonName then
    return false
  end

  if subject.organizationName ~= issuer.organizationName then
    return false
  end

  if subject.organizationalUnitName ~= issuer.organizationalUnitName then
    return false
  end

  if subject.countryName ~= issuer.countryName then
    return false
  end

  if subject.localityName ~= issuer.localityName then
    return false
  end

  if subject.stateOrProvinceName ~= issuer.stateOrProvinceName then
    return false
  end

  for i, _ in ipairs(subject.altNames) do
    if subject.altNames[i] ~= issuer.altNames[i] then 
      return false
    end
  end

  return true
end

-- Retrieve inforamtion (date and severity) about the blacklisted name entry
local function get_blacklist_information(names)
  if issuerBlacklist[names.commonName] ~= nil then
    return issuerBlacklist[names.commonName]
  elseif issuerBlacklist[names.organizationName] ~= nil then
    return issuerBlacklist[names.organizationName]
  end

  if names.altNames ~= nil then
    for _, altName in ipairs(names.altNames) do
      if issuerBlacklist[altName] ~= nil then
        return issuerBlacklist[altName]
      end
    end
  end

  return nil
end

-- Function to transform the certificate DN
local function transform_cert_dn(cert)
  local transformed_dn = {}
  
  -- Mapping of keys from the first format to the second format
  local key_mapping = {
    C = "countryName",
    ST = "stateOrProvinceName",
    L = "localityName",
    O = "organizationName",
    OU = "organizationalUnitName",
    CN = "commonName",
    emailAddress = "emailAddress"
  }

  -- Split the input DN into key-value pairs
  local temp_pairs = {}
  for key, value in cert:gmatch(" *([^=,]+) = ([^,]+) *") do
    temp_pairs[key] = value
  end

  -- Transform the DN using the key mapping
  for key, value in pairs(temp_pairs) do
    local new_key = key_mapping[key] or key
    transformed_dn[new_key] = value
  end

  return transformed_dn
end

-- Function to check if an ip is in a given range
local function ip_in_range(ip, min, max)
  local ipNum = socket.inet_pton(ip)
  local minNum = socket.inet_pton(min)
  local maxNum = socket.inet_pton(max)

  return ipNum >= minNum and ipNum <= maxNum
end
-------------------------------------------------------------------------------
-- OUTPUT funcitons (based on ssl-cert.nse)
-------------------------------------------------------------------------------

-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return outlib.sorted_by_key(output)
end

local function output_tab(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return {pem = cert.pem}
  end
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)

  o.pubkey = stdnse.output_table()
  o.pubkey.type = cert.pubkey.type
  o.pubkey.bits = cert.pubkey.bits
  -- The following fields are set in nse_ssl_cert.cc and mirror those in tls.lua
  if cert.pubkey.type == "rsa" then
    o.pubkey.modulus = openssl.bignum_bn2hex(cert.pubkey.modulus)
    o.pubkey.exponent = openssl.bignum_bn2dec(cert.pubkey.exponent)
  elseif cert.pubkey.type == "ec" then
    local params = stdnse.output_table()
    o.pubkey.ecdhparams = {curve_params=params}
    params.ec_curve_type = cert.pubkey.ecdhparams.curve_params.ec_curve_type
    params.curve = cert.pubkey.ecdhparams.curve_params.curve
  end

  if cert.extensions and #cert.extensions > 0 then
    o.extensions = {}
    for i, v in ipairs(cert.extensions) do
      local ext = stdnse.output_table()
      ext.name = v.name
      ext.value = v.value
      ext.critical = v.critical
      o.extensions[i] = ext
    end
  end
  o.sig_algo = cert.sig_algorithm

  o.validity = stdnse.output_table()
  for i, k in ipairs({"notBefore", "notAfter"}) do
    local v = cert.validity[k]
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = datetime.format_timestamp(v)
    end
  end
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  o.pem = cert.pem

  o.securityReport = {}
  o.securityReport.self_signed = securityReport.is_selfsigned
  o.securityReport.verified = securityReport.verified
  o.securityReport.validity = securityReport.validity
  o.securityReport.hostname_included =securityReport.name_validity
  o.securityReport.common_name_included = securityReport.cn_valid
  o.securityReport.subject_blacklisted = securityReport.is_blacklisted
  o.securityReport.subject_blacklisted_info = securityReport.blacklisted_info
  o.securityReport.issuer_blacklisted = securityReport.ca_is_blacklisted
  o.securityReport.issuer_blacklisted_info = securityReport.ca_blacklisted_info
  o.securityReport.dns_resolved = securityReport.dns_resolved
  o.securityReport.ip_in_range = securityReport.ip_in_range
  o.securityReport.warnings = securityReport.warnings
  return o
end

-------------------------------------------------------------------------------
-- CHECK functions
-------------------------------------------------------------------------------

-- Check the Validity field to ensure the certificate is still within its valid
-- date range

local function check_validity(cert)
  -- Get the current date
  local current_time = os.time(os.date("!*t"))

  -- Check certificate validity
  local valid_from = os.time(cert.validity.notBefore)
  local valid_to = os.time(cert.validity.notAfter)
 
  if current_time < valid_from then
    return CertValidity.NOT_YET_VALID
  elseif current_time > valid_to then
    return CertValidity.EXPIRED
  end

  -- Issue a warning if the validity period is very short, 
  -- e.g., one month, or long, e.g., 2 or more years.
  local warning = nil
  local validity_period = valid_to - valid_from
  if validity_period < 2678400 then
    warning = "WARNING: Short validity (less than one month)"
  elseif validity_period > 63072000 then
    warning = "WARNING: Long validity (more than two years)"
  end

  return CertValidity.VALID, warning
end

-- Check the Subject Alternative Name must contain the hostname or domain name
--  of the server, and if the Common Name field within the Subject field is
-- used, it must match one of the entries in the Subject Alternative Name field
local function check_name_validity(cert, host)
  local hostPresent = false
  local cnPresent = cert.subject.commonName == nil
  local idn_homograph_attack = false

  for _, name in pairs(cert.subject.altNames) do
    if name == host.ip then
      hostPresent = true
    end

    if check(name) then
      idn_homograph_attack = true
    end
  end

  if cert.subject.commonName ~= nil then
    for _, name in pairs(cert.subject.altNames) do
      if name == cert.subject.commonName then
        cnPresent = true
      end
    end
  end

  return hostPresent, cnPresent
end


-- Verify the signature
function verify_signature(cert, publicKey)
  return openssl.verify(publicKey, cert.pem, cert.sig_algorithm)
end

function check_authenticity(host, port, cert)
  local cmd = ("echo | openssl s_client -showcerts -connect %s:%s"):format(host.ip, port.number)
  local handle = io.popen(cmd)
  local certificate_chain = handle:read("*a")
  handle:close()
  
  local temp_cert = certificate_chain:match("(1 s:[^\n]*\n *i:[^\n]*\n[-]+BEGIN CERTIFICATE[-]+[^-]*[-]+END CERTIFICATE[-]+)")
  local ca_subject, _, ca_cert = temp_cert:match("[0-9]+ s:(.*)\n *i:(.*)\n([-]+BEGIN CERTIFICATE.*END CERTIFICATE[-]*)")

  -- Check the Issuer field in the server certificate should match the Subject 
  -- field of the CA certificate
  print("-----------AUTHENTICITY-----------")
  print(transform_cert_dn(ca_subject))
  ca_subject_table = transform_cert_dn(ca_subject)
  if(compare_subject_issuer(ca_subject_table, cert.issuer)) then
    verify_authenticity = true
    print(verify_authenticity)
  end
  
  -- Check the signature on the server certificate is valid and has been signed
  -- by the private key of the CA.
  local file = io.open("ca_cert.pem", "w")
  file:write(ca_cert)
  file:close()

  local file = io.open("server_cert.pem", "w")
  file:write(string.format("%s", cert.pem))
  file:close()

  local handle = io.popen("openssl verify -CAfile ca_cert.pem server_cert.pem")
  local verify_output = handle:read("*a")
  print(verify_output)
  verify_issuance = string.match(verify_output, "OK")
  handle:close()
end

local function check_self_signed(cert)
  -- SubjectName's CN is equal to IssuerName's CN
  if compare_subject_issuer(cert.subject, cert.issuer) then
    -- Check if the subject key can be used to validate the signature
    is_verified = verify_signature(cert, cert.pubkey)
    return true, is_verified
  else
    return false, false
  end
end

-- Check if the certificate's SubjectName or IssuerName (i.e., organization or
-- common name) or fingerprint (SHA1) are found in the blacklist of malicious servers, domains, or CAs.

local function check_blacklisted(cert)
  -- Check if names are found in the blacklist of malicious servers, domains,
  -- or CAs.
  local info = get_blacklist_information(cert.subject)
  local ca_info = get_blacklist_information(cert.issuer)

  if info == nil then
    info = signatureBlacklist[stdnse.tohex(cert:digest("sha1"), { separator = "", group = 4 })]
  end


  return info, ca_info
end

local function check_dns(cert, host)
  -- Check if the web server IP is the corresponding hostname IP
  local ip = host.ip:match("[0-9]+.[0-9]+.[0-9]+.[0-9]+")

  -- Check if the web server IP is present in the Subject Alternative Names 
  if ip == nil then
    for _, name in pairs(cert.subject.altNames) do
      ip = name:match("[0-9]+.[0-9]+.[0-9]+.[0-9]+")
      if ip ~= nil then
        break
      end
    end
  end

  -- Check if any domainname in the Subject Alternative Names 
  -- has a knonw ip address range
  for _, name in pairs(cert.subject.altNames) do
    if dnsRecords[name] ~= nil then
      local min, max = dnsRecords[name]
      return true, ip_in_range(ip, min, max)
    end
  end

  return false, false
end

local function check_ciphersuite(cert)
  local hashAlg, encAlg =  cert.sig_algorithm:match("^(.+)With(.+)Encryption$")
  local secureHash = false
  local secureEnc = encAlg == 'RSA' or encAlg == 'DSA' or encAlg == 'ECDSA' 
  if hashAlg ~= nil and hashAlg:match("^sha(.+)$") then
    local size = hashAlg:match("^sha([0-9]+)$")
    secureHash = tonumber(size) >= 256
  end

  return secureHash and secureEnc
end

local function output_str(cert)

  ------------------------------------------
  -- Certificate information
  ------------------------------------------
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
  local lines = {}

  lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end

  lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)

  lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
  lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
  lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm

  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = "MD5:   " .. 
    stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. 
    stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end

  ------------------------------------------
  -- Security information
  ------------------------------------------
  lines[#lines + 1] = "--------------------------------"
  lines[#lines + 1] = "CERTIFICATE SECURITY WARNINGS"
  lines[#lines + 1] = "--------------------------------"

  if securityReport.is_selfsigned then
    lines[#lines + 1] = "Self-signed: True"
  else
    lines[#lines + 1] = "Self-signed: False. Certificate issued by a Certification Authority."
  end

  if securityReport.verified then
    lines[#lines + 1] = "Certificate verified"
  else
    lines[#lines + 1] = "Certificate cannot be verified"
  end

  if securityReport.validity == CertValidity.VALID then
    lines[#lines + 1] = "Validity: Certificate is VALID"
  else
    lines[#lines + 1] = "Validity: Certificate is NOT VALID"
    if securityReport.validity == CertValidity.EXPIRED then
      lines[#lines + 1] = "Validity: Certificate exprired on " .. 
      date_to_string(cert.validity.notAfter)
    elseif securityReport.validity == CertValidity.NOT_YET_VALID then
      lines[#lines + 1] = "Validity: Certificate not valid before " .. 
      date_to_string(cert.validity.notBefore)
    end
  end

  if securityReport.name_validity then
    lines[#lines + 1] = "Certificate Subject Alternative Names contains hostname"
  else
    lines[#lines + 1] = "Certificate Subject Alternative Names does not contain hostname"
  end

  if not securityReport.cn_valid then
    lines[#lines + 1] = "Certificate Subject Alternative Names does not contain Subject Common Name"
  end

  if loadedBlackList then
    if securityReport.is_blacklisted then
      lines[#lines + 1] = "Blacklisted: Certificate Subject is blacklisted: on " ..
      securityReport.blacklisted_info.inclusion_date ..
      " with severity " .. securityReport.blacklisted_info.severity
    end

    if securityReport.ca_is_blacklisted then
      lines[#lines + 1] = "Blacklisted: Certificate CA is blacklisted: on " ..
      securityReport.ca_blacklisted_info.inclusion_date ..
      " with severity " .. securityReport.ca_blacklisted_info.severity
    end

    if not securityReport.is_blacklisted and not securityReport.ca_is_blacklisted then
      lines[#lines + 1] = "Blacklisted: False"
    end

  else
    lines[#lines + 1] = "Blacklist could not be loaded. Subejct and Issuer cannot be checked."
  end

  if securityReport.dns_resolved then 
    lines[#lines + 1] = "DNS resolved: True"
    if securityReport.ip_in_range then
      lines[#lines + 1] = "DNS: server ip is in a VALID RANGE"
    else
      lines[#lines + 1] = "DNS: server ip is NOT IN A VALID RANGE"
    end
  else
    lines[#lines + 1] = "DNS resolved: False"
  end

  for _, warning in ipairs(securityReport.warnings) do
    lines[#lines + 1] = warning
  end

  return table.concat(lines, "\n")
end

local function createSecurityReport(host, port, cert) 

  cert.subject.altNames = extract_alternative_names(cert)
  loadedBlackList = load_blacklist(blacklistFile)
  loadedDNS = load_dns(dnsPath)

  local is_selfsigned, is_verified = check_self_signed(cert)
  if is_selfsigned then
    securityReport.is_selfsigned = true
    securityReport.is_verified = is_verified
  else
    -- Check the authenticity and issuance by the Certification Authority
    securityReport.is_verified = check_authenticity(host, port, cert)
  end

  -- Check the Subject Alternative Name must contain the hostname or domain
  -- name of the server, and if the Common Name field within the Subject field 
  -- is used, it must match one of the entries in the Subject Alternative Name field.
  local name_validity, cn_valid, idn_homograph_attack = check_name_validity(cert, host)
  securityReport.name_validity = name_validity
  securityReport.cn_valid = cn_valid

  if idn_homograph_attack then
    table.insert(securityReport.warnings, "WARNING: Potential Punycode/IDN Homograph Attack")
  end
 
  -- Check the Validity field to ensure the certificate is still within its
  -- valid date range
 
  local validity, warning = check_validity(cert)
  securityReport.validity = validity
  if warning ~= nil then
    table.insert(securityReport.warnings, warning)
  end

  -- Check if the certificate's SubjectName or IssuerName (i.e., organization
  -- or common name) are found in the blacklist of malicious servers, domains,
  -- or CAs.
 
  if loadedBlackList then
    local cert_blacklisted_info, ca_blacklisted_info = check_blacklisted(cert)
    securityReport.is_blacklisted = cert_blacklisted_info ~= nil
    securityReport.blacklisted_info = cert_blacklisted_info
    securityReport.ca_is_blacklisted = ca_blacklisted_info ~= nil
    securityReport.ca_blacklisted_info = ca_blacklisted_info
  end

  -- Checkif the web server IP is the corresponding hostname IP. 
  -- The hostname is usually included in Subject Alternative Name or Common Name.

  local dns_resolved, ip_in_range = check_dns(cert, host)
  securityReport.dns_resolved = dns_resolved
  securityReport.ip_in_range = ip_in_range

  -- Issue a warning if the key length of public key is less than 2048 bits.
  if cert.pubkey.bits < 2048 then
    table.insert(securityReport.warnings, "WARNING: Public key size is too short (recomended 2048 or larger key)")
  end

  -- Issue a warning if the signature algorithm is not strong. It should be RSA
  -- or DSA or ECDSA with SHA256 or stronger.

  if not check_ciphersuite(cert) then
    table.insert(securityReport.warnings, "WARNING: signature algorithm is not strong (It should be RSA or DSA or ECDSA with SHA256 or stronger).")
  end
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  createSecurityReport(host, port, cert)

  return output_tab(cert), output_str(cert)
end