# Quick Reference

This document is a quick reference for information and commands needed once your environment is up and running.

- [Quick Reference](#quick-reference)
  - [List of Active Directory Users](#list-of-active-directory-users)
  - [List of AWS Instances](#list-of-aws-instances)
  - [Useful Commands](#useful-commands)
    - [SSH Tunnel to AWS Mac Instance for VNC](#ssh-tunnel-to-aws-mac-instance-for-vnc)

## List of Active Directory Users

The following usernames were randomly generated.

| **Username** | **Password**     | **Permissions** | **First** | **Last** |
| :----------- | :--------------- | :-------------- | :-------- | :------- |
| rburris      | `RbP4ssw0rd`     | Domain Admin    | Rolfe     | Burris   |
| hpotter      | `noax3teenohb~e` | Domain Admin    | Hope      | Potter   |
| fsewter      | `bZ1r2GGw#u9`    | Domain User     | Sewter    | Sewter   |
| wsign        | `aE7tewFhxc-a`   | Domain User     | Webster   | Sign     |
| dbrosio      | `pN6<3twi2`      | Domain User     | Dale      | Brosio   |

## List of AWS Instances

| **Hostname** | **IP**      | **OS**                 | **Auth**                               | **Notes**                                                   |
| :----------- | :---------- | :--------------------- | :------------------------------------- | :---------------------------------------------------------- |
| vhagar       | 10.90.30.20 | Windows Server 2019    | AD, local creds: `user: Administrator` | AD DC, retrieve password from AWS CLI                       |
| drogon       | 10.90.30.7  | Ubuntu                 | AD, or `user: ubuntu` with SSH key     | Joined to DC                                                |
| dreamfyre    | 10.90.30.22 | macOS 10.15 (Catalina) | AD, local creds: `user: ec2-user `     | Joined to DC, password for `ec2-user` assigned during setup |
| kali1        | 10.90.30.26 | Kali OS                | `user: kali`, use SSH key              |                                                             |

## Useful Commands

### SSH Tunnel to AWS Mac Instance for VNC

`ssh -L  5900:localhost:5900 -i ./oceanlotus ec2-user@MAC-IP`