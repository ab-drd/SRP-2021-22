# Izvještaj iz SRP laboratorijskih vježbi [6]

# Lab 6 - Linux permissions and ACLs

U ovoj smo se vježbi upoznali s osnovnim postupkom upravljanja korisničkim računima na Linux OS-u. Posebno smo naglasili kontrolu pristupa datotekama, programima i drugim resursima Linux sustava.

## Korisnički račun

### Osnove

U Linux-u svaki korisnik (*user*, *owner*) može biti vlasnik datoteke ili programa. Korisnici su jedinstveni po svom identifikatoru, *User ID* (*UID*). Postoje i grupe (*group*) te svaki korisnik mora pripadati barem jednoj. Linux grupe imaju svoje jedinstvene identifikatore, *Group ID (GID)*.

Naredbom `id` možemo provjeriti jedinstvene identifikatore na lokalnom računalu, kao i pripadnost grupama:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ id
uid=1000(student) gid=1000(student) groups=1000(student),4(adm),
20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),
44(video),46(plugdev),114(netdev),1001(docker)
```

Naredbom `groups` možemo provjeriti grupe kojima pripadamo (kao korisnik *student*, jer smo trenutno logiran kao on):

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A207/ab$ groups
student adm dialout cdrom floppy sudo audio dip video plugdev netdev docker
```

### Novi korisnički račun

Možemo kreirati novi korisnički račun naredbom `adduser`, pri čemu moramo biti dio **sudo** grupe, jer je izrada novog računa moguća samo s administratorskim ovlastima.

Pokušamo li napraviti račun bez ključne riječi **sudo**, sustav nas upozorava da nemamo prava:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ adduser alice
adduser: Only root may add a user or group to the system.
```

Izradimo sada novog korisnika kao administrator:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo adduser alice
[sudo] password for student:
Adding user `alice' ...
Adding new group `alice' (1002) ...
Adding new user `alice' (1001) with group `alice' ...
Creating home directory `/home/alice' ...
Copying files from `/etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for alice
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n]
```

Sada se možemo ulogirati kao novonapravljeni korisnik:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ su - alice
Password:
alice@DESKTOP-7Q0BASR:~$
```

Naredba `whoami` ispisuje naše korisničko ime, dok naredbom `id` možemo provjeriti jedinstvene identifikatore i pripadnost grupama:

```bash
alice@DESKTOP-7Q0BASR:~$ whoami
alice
alice@DESKTOP-7Q0BASR:~$ id
uid=1001(alice) gid=1002(alice) groups=1002(alice)
```

Možemo se izlogirati naredbom exit:

```bash
alice@DESKTOP-7Q0BASR:~$ exit
```

Naredba `deluser` briše korisnika navedenog korisničkog imena. Za nju su također potrebna administratorska prava.

U svrhe laboratorijske vježbe, napravit ćemo još jedan korisnički račun i ulogirati se na njega u novom prozoru:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo adduser bob
Adding user `bob' ...
Adding new group `bob' (1003) ...
Adding new user `bob' (1002) with group `bob' ...
Creating home directory `/home/bob' ...
Copying files from `/etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for bob
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n]
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ su - bob
Password:
bob@DESKTOP-7Q0BASR:~$ id
uid=1002(bob) gid=1003(bob) groups=1003(bob)
```

## Standardna prava pristupa datotekama

### Osnove prava pristupa

Napravit ćemo novi direktorij i unutar njega tekstualnu datoteku.

Naredbom `pwd` možemo saznati naš trenutni direktorij:

```bash
alice@DESKTOP-7Q0BASR:~$ pwd
/home/alice
```

Unutar njega radimo novi direktorij, `srp`, i unutar njega tekstualnu datoteku `security.txt` sadržaja `"Hello world"`:

```bash
alice@DESKTOP-7Q0BASR:~$ mkdir srp
alice@DESKTOP-7Q0BASR:~$ cd srp
alice@DESKTOP-7Q0BASR:~/srp$ echo "Hello world" > security.txt
```

Naredbom `ls -l` dobit ćemo uvid u datoteke unutar direktorija, kao i prava koja su asocirana uz njih, njihovu veličinu i datum:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ ls -l
total 4
-rw-rw-r-- 1 alice alice 12 Jan 10 13:17 security.txt
```

Format funkcionira ovako: rwxrwxrwx - prava korisnika (user), prava grupa (group), prava za ostale (other).

Po gornjem zapisu -rw-rw-r-- zaključujemo da korisnik može čitati i pisati u datoteku, grupe mogu isto to, a ostali mogu samo čitati.

Malo formatirainiji prikaz prava, npr. direktorija `srp`:

```bash
alice@DESKTOP-7Q0BASR:~$ getfacl srp
# file: srp
# owner: alice
# group: alice
user::rwx
group::rwx
other::r-x
```

Te prava datoteke `security.txt`:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
# file: security.txt
# owner: alice
# group: alice
user::rw-
group::rw-
other::r--
```

Kao korisnik imamo pravo čitati datoteku, pa i možemo naredbom `cat`:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello world
```

### Uređivanje prava korisnika

Korisnik može uređivati prava nad datotekama čiji je on vlasnik.

To se radi naredbom `chmod` i kombinacijama parametra.

Na primjer, ako želimo korisniku ukinuti pravo čitanja datoteke security.txt, napravit ćemo sljedeće:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ chmod u-r security.txt
```

Sada vidimo da nam sustav ne dopušta čitanje datoteke:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ cat security.txt
cat: security.txt: Permission denied
```

Također vidimo da nam je pravo čitanja ukinuto:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ getfacl security.txt
# file: security.txt
# owner: alice
# group: alice
user::-w-
group::rw-
other::r--
```

Pravo si možemo i vratiti:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ chmod u+r security.txt
alice@DESKTOP-7Q0BASR:~/srp$ cat security.txt
Hello world
```

Ukinut ćemo si pravo čitanja sadržaja `srp` direktorija. Prvo moramo izaći iz njega, a usput možemo ponovno provjeriti koja su nam trenutna prava nad direktorijem:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ cd ..
alice@DESKTOP-7Q0BASR:~$ getfacl srp/
# file: srp/
# owner: alice
# group: alice
user::rwx
group::rwx
other::r-x
```

Sad ćemo si oduzeti pravo ispisivanja sadržaja direktorija i testirati ga naredbom `cat` nad `security.txt` datotekom, koja je unutar njega.

```bash
alice@DESKTOP-7Q0BASR:~$ chmod u-x srp
alice@DESKTOP-7Q0BASR:~$ getfacl srp/
# file: srp/
# owner: alice
# group: alice
user::rw-
group::rwx
other::r-x

alice@DESKTOP-7Q0BASR:~$ cat srp/security.txt
cat: srp/security.txt: Permission denied
```

Pokušamo li pročitati security.txt preko srp direktorija kao neki drugi korisnik, npr. bob, vidjet ćemo da je to dozvoljeno, jer je bob dio `other` kategorije.

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ su - bob
Password:
bob@DESKTOP-7Q0BASR:~$ cat /home/alice/srp/security.txt
Hello world
```

Možemo i oduzeti pravo čitanja bobu (odnosno svim `other` korisnicima):

```bash
alice@DESKTOP-7Q0BASR:~/srp$ chmod o-r security.txt

bob@DESKTOP-7Q0BASR:~$ cat /home/alice/srp/security.txt
cat: /home/alice/srp/security.txt: Permission denied
```

Pokušajmo sada na drugi način vratiti bobu pristup čitanju sadržaja direktorija `srp`. Dodat ćemo boba u grupu `alice`, koja ima pravo *(r)ead* nad direktorijem. Tako će se bob sada voditi pod pravima grupe, a ne pod other. Ovo ne možemo napraviti kao korisnik alice, jer taj korisnički račun nije dio grupe sudo i tako nema administratorska prava:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ usermod -aG alice bob
usermod: Permission denied.
usermod: cannot lock /etc/passwd; try again later.
alice@DESKTOP-7Q0BASR:~/srp$ sudo usermod -aG alice bob
[sudo] password for alice:
alice is not in the sudoers file.  This incident will be reported.
```

Zato ćemo se izlogirati iz alice i promijeniti pravo preko student korisnika:

```bash
alice@DESKTOP-7Q0BASR:~/srp$ exit
logout
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo usermod -aG alice bob
[sudo] password for student:
```

Pokušamo li odmah izlistati security.txt, vidjet ćemo da ne možemo. To je zato što se još uvijek vodimo pod starim pravima, koja smo imali kad smo se ulogirali. Kako bismo dobili nova prava, trebamo se izlogirati i ponovno ulogirati.

```bash
bob@DESKTOP-7Q0BASR:~$ cat /home/alice/srp/security.txt
cat: /home/alice/srp/security.txt: Permission denied
bob@DESKTOP-7Q0BASR:~$ exit

student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ su - bob
Password:
bob@DESKTOP-7Q0BASR:~$ cat /home/alice/srp/security.txt
Hello world
```

### /etc/shadow datoteka

Pokušajmo bob pročitati sadržaj `shadow` datoteke:

```bash
bob@DESKTOP-7Q0BASR:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
```

Sustav nam kaže da ne možemo listati sadržaj. Otkrijmo zašto!

```bash
bob@DESKTOP-7Q0BASR:~$ getfacl etc/shadow
# file: etc/shadow
# owner: root
# group: shadow
user::rw-
group::r--
other::---
```

bob je `other` korisnik, pa on nema nikakva prava nad `shadow` datotekom.

## ACL (Access Control Lists) - kontrola pristupa

Prvo uklonimo boba iz grupe alice kako on ponovno ne bi imao pristup sadržaju `security.txt` datoteke:

```bash
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507/ab$ sudo gpasswd -d bob alice
Removing user bob from group alice
```

Sada možemo pomoću liste kontrole pristupa postaviti boba u posebnu grupu! Kada sustav vidi da bob pokušava izlistati sadržaj `security.txt` datoteke, vidjet će da za njega postoje posebna prava i on će se pod njima voditi:

```bash
student@DESKTOP-7Q0BASR:/home/alice/srp$ sudo setfacl -m u:bob:r security.txt
student@DESKTOP-7Q0BASR:/home/alice/srp$ getfacl security.txt
# file: security.txt
# owner: alice
# group: alice
user::rw-
user:bob:r--
group::rw-
mask::rw-
other::---
```

## Linux procesi i kontrola pristupa

Napravit ćemo novu datoteku, lab_6.py i u nju kopirati kod koji nam je dao profesor.

```bash
student@DESKTOP-7Q0BASR:~$ code .
```

lab_6.py kod:

```python
import os

print('Real (R), effective (E) and saved (S) UIDs:') 
print(os.getresuid())

with open('/home/alice/srp/security.txt', 'r') as f:
    print(f.read())
```

Prava nad skriptom:

```bash
student@DESKTOP-7Q0BASR:~$ getfacl lab_6.py
# file: lab_6.py
# owner: student
# group: student
user::rw-
group::r--
other::r--
```

Pokušamo li izvršiti skriptu, naiđemo na PermissionError!

```bash
student@DESKTOP-7Q0BASR:~$ python3 lab_6.py
Real (R), effective (E) and saved (S) UIDs: (1000, 1000, 1000)
Traceback (most recent call last):
  File "lab_6.py", line 5, in <module>
    with open('/home/alice/srp/security.txt', 'r') as f:
PermissionError: [Errno 13] Permission denied: '/home/alice/srp/security.txt'
```

Naime, na problem smo naišli zbog konteksta u kojem se nalazimo, a to je korisnik student.

Pokušamo li istu stvar napraviti kao bob:

```bash
bob@DESKTOP-7Q0BASR:~$ python3 /home/student/lab_6.py
Real (R), effective (E) and saved (S) UIDs: (1002, 1002, 1002)

Hello world
```

bob ima pravo čitanja `security.txt` datoteke i zato nismo naišli na PermissionError!

### Mehanizam efektivnog vlasnika procesa

Provjerimo prava koja daje passwd naredba:

```bash
bob@DESKTOP-7Q0BASR:~$ ls -l $(which passwd)
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
```

**s** flag je specijalni flag koji daje posebna prava onome koji poziva naredbu.

Pokrenimo proces promjene lozinke kao bob i ostavimo prozor upaljen bez pisanja:

```bash
bob@DESKTOP-7Q0BASR:~$ passwd
Changing password for bob.
(current) UNIX password:
```

U drugoj konzoli pokrenimo naredbu `ps`. Ona sa sljedećim parametrima ispisuje tekuće procese sa njihovim stvarnim i efektivnim vlasnicima:

```bash
student@DESKTOP-7Q0BASR:~$ ps -eo pid,ruid,euid,suid,cmd | grep passwd
  747  1002     0     0 passwd
  750  1000  1000  1000 grep --color=auto passwd
```

Primjećujemo da je efektivni id korisnika koji zove passwd naredbu 0 (root), dok je pravi korisnik 1002 (bob). To zapravo znači da bob privremeno, odnosno samo za vrijeme izvršavanja naredbe passwd dobije prava roota, kako bi si mogao promijeniti lozinku.