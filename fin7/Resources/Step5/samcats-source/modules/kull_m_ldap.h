/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <Winldap.h>
#include <WinBer.h>
#include "kull_m_string.h"

BOOL kull_m_ldap_getLdapAndRootDN(PCWCHAR system, PCWCHAR nc, PLDAP *ld, PWCHAR *rootDn);
PWCHAR kull_m_ldap_getRootDomainNamingContext(PCWCHAR nc, LDAP *ld);