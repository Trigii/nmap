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
-- file: ath to the file with the blacklist(blacklist.csv)
-- @usage nmap -sV <target-ip> --script=./untrustedX509certs.nse --script-args file=blacklistfile.csv
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
--   <elem key="organizationalUnitName">Terms of use at https://www.verisign.com/rpa (c)06</elem>
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

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-------------------------------------------------------------------------------
-- Global variables
-------------------------------------------------------------------------------

-- Define a table to store the blacklist
local issuerBlacklist = {}

local loadedBlackList = false

-------------------------------------------------------------------------------
-- ENUM definitions
-------------------------------------------------------------------------------

CertValidity = {
  NOT_YET_VALID = 1,
  EXPIRED = 2,
  VALID = 3
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

-- Get the common name of a cert part (subject or issuer)

local function extract_names(names)
  local cName = ""
  local altName = ""
  local orgName = ""
  
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    local v = names[k]
    if v then
      if k == "commonName" then
        cName = maybe_decode(v) or ""
      end
      if k == "organizationName" then
        orgName = maybe_decode(v) or ""
      end
      if k == "AlternativeName" then
        altName = maybe_decode(v) or ""
      end
    end
  end

  return cName, altName, orgName
end


-- Load the blacklist from a file
function load_blacklist(file)
  local file_handle = io.open(file, "r")
  if not file_handle then
    return false
  end

  for line in file_handle:lines() do
    local date, issuer, severity = line:match("([^;]+);([^;]+);([^;]+)")
    if date and issuer and severity then
      issuerBlacklist[issuer] = {
        severity = severity,
        inclusion_date = date
      }
    end
  end

  file_handle:close()
  return true
end
-- Check if a name is in the blacklist
function is_issuer_blacklisted(names)
  local cName, altName, orgName = extract_names(names)
  return issuerBlacklist[cName] ~= nil or issuerBlacklist[altName] ~= nil or issuerBlacklist[orgName] ~= nil
end

-- Retrieve inforamtion (date and severity) about the blacklisted name entry
function get_blacklist_information(names)
  local cName, altName, orgName = extract_names(names)

  if issuerBlacklist[cName] ~= nil then
    return issuerBlacklist[cName]
  elseif issuerBlacklist[altName] ~= nil then
    return issuerBlacklist[altName]
  end

  return issuerBlacklist[orgName]
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
  return o
end


-------------------------------------------------------------------------------
-- CHECK functions
-------------------------------------------------------------------------------

local function check_authenticity(cert)
  -- Check the Issuer field in the server certificate should match the Subject 
  -- field of the CA certificate
  
  -- Check the signature on the server certificate is valid and has been signed
  -- by the private key of the CA.
end

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

  return CertValidity.VALID
end

-- Verify the signature
function verifySignature(cert, publicKey)
  local is_verified = openssl.verify(publicKey, cert.pem, cert.sig_algorithm)
  
  if is_verified then
    return true
  else
    return false
  end
end

local function check_self_signed(cert)
  -- SubjectName's CN is equal to IssuerName's CN
  if cert.subject == cert.issuer then
    -- Check if the subject key can be used to validate the signature
    is_verified = verifySignature(cert, cert.pubkey)
    return true, is_verified
  else
    return false, false
  end
end

-- Check if the certificate's SubjectName or IssuerName (i.e., organization or
-- common name) 
-- are found in the blacklist of malicious servers, domains, or CAs.

local function check_blacklisted(names)
  -- Check if names are found in the blacklist of malicious servers, domains,
  -- or CAs.

  if is_issuer_blacklisted(names) then
    local info = get_blacklist_information(names)
    return true, info
  end

  return false, nil
end

local function check_dns(cert)
  -- Check if the web server IP is the corresponding hostname IP
end

local function output_str(cert)
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
    lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end

  -- Security information
  lines[#lines + 1] = "CERTIFICATE SECURITY WARNINGS"

  local authenticity = check_authenticity(cert)
  if authenticity then
    lines[#lines + 1] = "Certificate authenticity failed"
  end

  local validity = check_validity(cert)
  if validity == CertValidity.VALID then
    lines[#lines + 1] = "Validity: OK"
  else
    lines[#lines + 1] = "Certificate not valid"
    if validity == CertValidity.EXPIRED then
      lines[#lines + 1] = "Certificate exprired on " .. date_to_string(cert.validity.notAfter)
    elseif authenticity == CertValidity.NOT_YET_VALID then
      lines[#lines + 1] = "Certificate not valid before " .. date_to_string(cert.validity.notBefore)
    end
  end


  -- Check if the certificate's SubjectName or IssuerName (i.e., organization
  -- or common name) are found in the blacklist of malicious servers, domains,
  -- or CAs.

  if loadedBlackList then
    local cert_is_blacklisted, info = check_blacklisted(cert.subject)
    if cert_is_blacklisted then
      lines[#lines + 1] = "Certificate Subject is blacklisted"
      if info ~= nil then
        lines[#lines + 1] = "Subject blacklisted on " .. info.inclusion_date .. " with severity " .. info.severity
      end
    end
  
    local ca_is_blacklisted, info = check_blacklisted(cert.issuer)
    if ca_is_blacklisted then
      lines[#lines + 1] = "Certificate CA is blacklisted"
      if info ~= nil then
        lines[#lines + 1] = "CA blacklisted on " .. info.inclusion_date .. " with severity " .. info.severity
      end

    end
  else
    lines[#lines + 1] = "Blacklist could not be loaded. Subejct and Issuer cannot were not checked."
  end

  local is_selfsigned, is_verified = check_self_signed(cert)
  if is_selfsigned then
    lines[#lines + 1] = "Certificate is self-signed"
    if ~is_verified then
      lines[#lines + 1] = "Certificate cannot be verified"
    else
      lines[#lines + 1] = "Certificate verified"
    end
  end

  return table.concat(lines, "\n")
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  loadedBlackList = load_blacklist(blacklistFile)

  return output_tab(cert), output_str(cert)
end