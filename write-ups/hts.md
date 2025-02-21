## Basic

### Level 1

Just view page source. The password is a HTML comment `6cc75738`.

### Level 2

If he did not upload the password file, the password is a blank entry.

### Level 3

Viewing page source, we see the entry
```html
<input type="hidden" name="file" value="password.php" />
```

Therefore, we just go to `https://www.hackthissite.org/missions/basic/3/password.php`. The password is `832a8b8d`.

### Level 4

Use `firefox` to click "Inspect" on the "Send password to Sam" button. Edit the email address value
```html
<input type="hidden" name="to" value="your@email.com">
```
and click "Send password to Sam" button. The password `a825fedf` will be sent to your email.

### Level 5

I applied the same method of Level 4 and it worked. I don't know what is the catch.


### Level 6

The encrypted password is `e39i5fh>`.

If I put `aaaaaaaa` as input, the output is `abcdefgh`.

So, the password has 8 letters and the encryption algorithm just sums $i$ to the $i$-th char in the string (ASCII format). We then write a little `decrypt.c` program that subtracts $i$ to the $i$-th char (the inverse process).
```c
#include <stdio.h>
int main() {
    char passwd[9];
    scanf("%8s", passwd);
    for (int i = 0; i < 8; i++)
        passwd[i] -= i;
    printf("%s\n", passwd);
}
```

Using `e39i5fh>` as input, we obtain `e27f1ab7` as the decrypted password.

### Level 7

This one is based on code injection. Just put `; ls` in the year for the calendar program. That will list the files on the server. There is one called `k1kh31b1n55h.php`.

Going to `https://www.hackthissite.org/missions/basic/7/k1kh31b1n55h.php`, the password is `befb560f`.

### Level 8

Look at [OWASP SSI](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)

The SSI to use is
```php
<!--#exec cmd="ls" -->
```

The obscured file is `https://www.hackthissite.org/missions/basic/8/au12ha39vc.php` and the password is `fb3fbb32`.

### Level 9

Go back to level 8 and use the following SSI:
```php
<!--#exec cmd="ls ../../9" -->
```

Then go to `https://www.hackthissite.org/missions/basic/9/p91e283zc3.php`. The password is `21987dd6`.

### Level 10

Use Firefox Inspect, go to the Storage/Cookies section and change `level10_authorized` to `yes`.

### Level 11

Directory enumeration with `gobuster`:
```bash
gobuster dir -x php -w Workspace/wordlists/directory-list-2.3-small.txt \
-u https://www.hackthissite.org/missions/basic/11/
```

The file `index.php` and directory `e/` exist. Going to `https://www.hackthissite.org/missions/basic/11/e`, we are prompted to go to the directory `e/l/t/o/n`. Knowing that Sam uses `apache`, we search for `.htaccess` in this directory. We get
```html
IndexIgnore DaAnswer.* .htaccess
<Files .htaccess>
require all granted
</Files>
```

The file `DaAnswer` seems suspicious, so we go to `https://www.hackthissite.org/missions/basic/11/e/l/t/o/n/DaAnswer`. We get
```bash
The answer is somewhere! Just look a little harder.
```
This is a charade. The password is `somewhere`. Go to `index.php` and submit it. The level is completed.

## Extended Basics

### Level 1

To crash the C program just enter a long enough string (200 or more characters), because an overflow will occur.

## Javascript

### Level 1

This is an idiot's test. Just view page source and check `javascript` code. We easily see that the password is `cookies`.
