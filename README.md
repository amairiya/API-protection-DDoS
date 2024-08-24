Requêtes avec des Chaînes Suspectes

Injection SQL
```js
SELECT * FROM
UNION SELECT
DROP TABLE
INSERT INTO
UPDATE SET
OR 1=1
';--
admin' --
```

Cross-Site Scripting (XSS)
```js
<script>
</script>
javascript:
eval(
document.cookie
onload=
alert(
location.href=
```

Command Injection
```js
; ls
| whoami
&& echo
$(uname -a)
| cat /etc/passwd
Path Traversal
../
..\\
%2e%2e%2f
%2e%2e%5c
../../etc/passwd
..%2f..%2f
```

XML External Entity (XXE) Injection
```js
<!DOCTYPE
ENTITY xxe SYSTEM
file:///
!ENTITY xxe SYSTEM
<!ENTITY % file SYSTEM
Local File Inclusion (LFI) / Remote File Inclusion (RFI)
php://input
file://
http://
../
/etc/passwd
../config.php
```

Remote Code Execution (RCE)
```js
system(
exec(
shell_exec(
passthru(
phpinfo()
```

Brute Force and Enumeration
```js
username=admin&password=
user=admin
password=
login=
auth_token=
id=1 UNION SELECT
HTTP Header Injection
Host: example.com
X-Forwarded-For:
Referer:
Content-Length:
Transfer-Encoding: chunked
```

Denial of Service (DoS)
```js
GET /? (extremely large number of parameters)
POST / (with excessively large payloads)
X-Requested-With: XMLHttpRequest (with large volume)
```
