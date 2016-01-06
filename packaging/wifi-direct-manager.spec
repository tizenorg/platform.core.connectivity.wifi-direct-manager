Name:		wifi-direct-manager
Summary:	Wi-Fi Direct manger
Version:	1.2.111
Release:	1
Group:      Network & Connectivity/Wireless
License:    Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:  pkgconfig(libnl-2.0)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(aul)
BuildRequires:	pkgconfig(cynara-client)
BuildRequires:	pkgconfig(cynara-creds-socket)
BuildRequires:	pkgconfig(cynara-session)

BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:	cmake
#BuildRequires:  model-build-features
Requires:	net-tools
#Requires:	sys-assert
#Requires:	tizen-coreutils
Requires: toybox-symlinks-dhcpd
Requires: toybox-symlinks-dhcp

%description
Wi-Fi Direct manager

%package -n wifi-direct-plugin-wpasupplicant
Summary:    Wifi direct plugin for wpa supplicant
Group:      Network & Connectivity/Wireless
Requires:   %{name} = %{version}-%{release}

%description -n wifi-direct-plugin-wpasupplicant
Wifi direct plugin for wpa supplicant


%prep
%setup -q

%build

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%ifarch %{arm}
export ARCH=arm
%else

%if 0%{?simulator}
export ARCH=emul
%else
export ARCH=i586
%endif

%endif

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCHITECTURE=$ARCH \
%if 0%{?model_build_feature_wlan_concurrent_mode}
	-DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
%endif
%if ! 0%{?model_build_feature_network_tethering_disable}
	-DTIZEN_TETHERING_ENABLE=0 \
%endif
%if "%{profile}" == "wearable"
        -DTIZEN_FEATURE_SERVICE_DISCOVERY=0 \
        -DTIZEN_FEATURE_WIFI_DISPLAY=0 \
%else
%if "%{profile}" == "mobile"
%if "%{?tizen_target_name}" == "TM1"
	-DTIZEN_WLAN_BOARD_SPRD=1 \
%endif
        -DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
        -DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
        -DTIZEN_FEATURE_WIFI_DISPLAY=1 \
        -DTIZEN_FEATURE_DEFAULT_CONNECTION_AGENT=0 \
        -DCTRL_IFACE_DBUS=1 \
        -DTIZEN_MOBILE=1 \
%else
%if "%{profile}" == "tv"
	-DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
	-DTIZEN_WLAN_CONCURRENT_ENABLE=0 \
	-DTIZEN_FEATURE_WIFI_DISPLAY=1 \
	-DCTRL_IFACE_DBUS=1 \
	-DTIZEN_WIFI_MODULE_BUNDLE=0 \
	-DTIZEN_TV=1 \
	-DTIZEN_TV_BOARD_PRD=1 \
%endif
%endif
%endif
%if "%{?_lib}" == "lib64"
	-DTIZEN_ARCH_64=1 \
%endif
-DCMAKE_LIB_DIR=%{_libdir}

make %{?_smp_mflags}


%install
rm -rf %{buildroot}

%make_install
#%__strip %{buildroot}%{_libdir}/wifi-direct-plugin-wpasupplicant.so
#%__strip %{buildroot}%{_bindir}/wfd-manager

#License
mkdir -p %{buildroot}%{_datadir}/license
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}%{_datadir}/license/%{name}
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}%{_datadir}/license/wifi-direct-plugin-wpasupplicant

%post
#TV profile uses default XU3 device which creates wlan interface only
%if "%{profile}" == "tv"
# Comment it for temp puprose. Tizen TV Board supports p2p0 interface
#chmod 644 /usr/etc/wifi-direct/dhcpd.wlan.conf
chmod 644 /usr/etc/wifi-direct/dhcpd.p2p.conf
%else
chmod 644 /usr/etc/wifi-direct/dhcpd.p2p.conf
%endif
chmod 755 /usr/bin/dhcpd-notify.sh
chmod 755 /usr/etc/wifi-direct/udhcp_script.non-autoip
chmod 755 /usr/bin/wifi-direct-server.sh
chmod 755 /usr/bin/wifi-direct-dhcp.sh
chmod 755 /usr/sbin/p2p_supp.sh

%if "%{profile}" == "tv"
	if [ ! -d /opt/var/lib/misc ]; then
		mkdir -p /opt/var/lib/misc
	fi

	touch /opt/var/lib/misc/dhcpd.leases
	chmod 666 /opt/var/lib/misc/dhcpd.leases
%else
	if [ ! -d /var/lib/misc ]; then
		mkdir -p /var/lib/misc
	fi

	touch /var/lib/misc/dhcpd.leases
	chmod 666 /var/lib/misc/dhcpd.leases
%endif

%postun


%files
%manifest wifi-direct-manager.manifest
%defattr(-,root,root,-)
%{_bindir}/wfd-manager
#TV profile uses default XU3 device which creates wlan interface only
%if "%{profile}" == "tv"
/usr/etc/wifi-direct/dhcpd.p2p.conf
#/usr/etc/wifi-direct/dhcpd.wlan.conf
%else
/usr/etc/wifi-direct/dhcpd.p2p.conf
%endif
/usr/etc/wifi-direct/udhcp_script.non-autoip
/usr/etc/wifi-direct/p2p_supp.conf
/opt/etc/p2p_supp.conf
/usr/etc/wifi-direct/ccode.conf
/opt/etc/persistent-peer
%{_bindir}/dhcpd-notify.sh
%{_bindir}/wifi-direct-server.sh
%{_bindir}/wifi-direct-dhcp.sh
%{_sbindir}/p2p_supp.sh
%attr(755,-,-) %{_bindir}/dhcpd-notify.sh
%attr(755,-,-) %{_bindir}/wifi-direct-server.sh
%attr(755,-,-) %{_bindir}/wifi-direct-dhcp.sh
%attr(755,-,-) /usr/etc/wifi-direct/udhcp_script.non-autoip
%attr(755,-,-) %{_sbindir}/p2p_supp.sh
%attr(644,-,-) %{_datadir}/license/%{name}

%files -n wifi-direct-plugin-wpasupplicant
%manifest wifi-direct-plugin-wpasupplicant.manifest
%defattr(-,root,root,-)
%{_libdir}/wifi-direct-plugin-wpasupplicant.so
%attr(644,-,-) %{_datadir}/license/wifi-direct-plugin-wpasupplicant
