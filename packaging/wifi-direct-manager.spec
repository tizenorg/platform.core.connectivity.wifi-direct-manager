Name:		wifi-direct-manager
Summary:	Wi-Fi Direct manger
Version:	1.2.159
Release:	1
Group:      Network & Connectivity/Wireless
License:    Apache-2.0
Source0:	%{name}-%{version}.tar.gz
Source1:	dbus-wfd-manager.conf
Source2:	net.wifidirect.service
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:  pkgconfig(libnl-2.0)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(aul)

BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(libsystemd-login)

BuildRequires: pkgconfig(libtzplatform-config)

BuildRequires:	cmake
#BuildRequires:  model-build-features
Requires:	net-tools
#Requires:	sys-assert
#Requires:	tizen-coreutils
Requires: toybox-symlinks-dhcpd
Requires: toybox-symlinks-dhcp

%description
Manager for handling wifi-direct functionalities

%package -n wifi-direct-plugin-wpasupplicant
Summary:    Wifi direct plugin for wpa supplicant
Group:      Network & Connectivity/Wireless
Requires:   %{name} = %{version}-%{release}

%description -n wifi-direct-plugin-wpasupplicant
Wi-Fi direct manager plugin to abstract wpa_supplicant


%prep
%setup -q
chmod 644 %{SOURCE0}
chmod 644 %{SOURCE1}
chmod 644 %{SOURCE2}
cp -a %{SOURCE1} ./wfd-manager.conf
cp -a %{SOURCE2} .

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
%if "%{profile}" == "common"
        -DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
        -DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
        -DTIZEN_FEATURE_WIFI_DISPLAY=1 \
        -DTIZEN_FEATURE_IP_OVER_EAPOL=1 \
        -DCTRL_IFACE_DBUS=1 \
        -DTIZEN_DEBUG_DBUS_VALUE=1 \
        -DTIZEN_COMMON=1 \
%else
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
        -DTIZEN_FEATURE_DEFAULT_CONNECTION_AGENT=1 \
        -DTIZEN_FEATURE_IP_OVER_EAPOL=1 \
        -DCTRL_IFACE_DBUS=1 \
        -DTIZEN_DEBUG_DBUS_VALUE=1 \
        -DTIZEN_MOBILE=1 \
        -DTIZEN_FEATURE_ASP=1 \
%else
%if "%{profile}" == "tv"
	-DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
	-DTIZEN_WLAN_CONCURRENT_ENABLE=0 \
	-DTIZEN_FEATURE_WIFI_DISPLAY=1 \
	-DTIZEN_FEATURE_IP_OVER_EAPOL=1 \
	-DCTRL_IFACE_DBUS=1 \
	-DTIZEN_DEBUG_DBUS_VALUE=1 \
	-DTIZEN_WIFI_MODULE_BUNDLE=0 \
	-DTIZEN_TV=1 \
%endif
%endif
%endif
%endif
%if "%{?_lib}" == "lib64"
	-DTIZEN_ARCH_64=1 \
%endif
-DLIB_DIR=%{_libdir} \
-DBIN_DIR=%{_bindir} \
-DSBIN_DIR=%{_sbindir} \
-DTZ_SYS_RO_ETC=%TZ_SYS_RO_ETC \
-DTZ_SYS_VAR=%TZ_SYS_VAR \
-DTZ_SYS_ETC=%TZ_SYS_ETC \
-DTZ_SYS_RUN=%TZ_SYS_RUN

make %{?_smp_mflags}


%install
rm -rf %{buildroot}

%make_install

mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
cp wfd-manager.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/wfd-manager.conf
mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services/
cp net.wifidirect.service %{buildroot}%{_datadir}/dbus-1/system-services/net.wifidirect.service

%post
chmod 644 %{TZ_SYS_RO_ETC}/wifi-direct/dhcpd.conf
chmod 755 %{_bindir}/dhcpd-notify.sh
chmod 755 %{TZ_SYS_RO_ETC}/wifi-direct/udhcp_script.non-autoip
chmod 755 %{_bindir}/wifi-direct-server.sh
chmod 755 %{_bindir}/wifi-direct-dhcp.sh
chmod 755 %{_sbindir}/p2p_supp.sh

if [ ! -d %{TZ_SYS_VAR}/lib/misc ]; then
	mkdir -p %{TZ_SYS_VAR}/lib/misc
fi

touch %{TZ_SYS_VAR}/lib/misc/dhcpd.leases
chmod 666 %{TZ_SYS_VAR}/lib/misc/dhcpd.leases

%files
%manifest wifi-direct-manager.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_bindir}/wfd-manager
%config %TZ_SYS_RO_ETC/wifi-direct/ccode.conf 
%config %TZ_SYS_RO_ETC/wifi-direct/dhcpd.conf
%config %TZ_SYS_RO_ETC/wifi-direct/p2p_supp.conf
%config %TZ_SYS_RO_ETC/wifi-direct/udhcp_script.non-autoip
%config %{_sysconfdir}/dbus-1/system.d/wfd-manager.conf
%TZ_SYS_RO_ETC/wifi-direct/ccode.conf
%TZ_SYS_RO_ETC/wifi-direct/dhcpd.conf
%TZ_SYS_RO_ETC/wifi-direct/p2p_supp.conf
%TZ_SYS_RO_ETC/wifi-direct/udhcp_script.non-autoip
%TZ_SYS_ETC/p2p_supp.conf
%{_bindir}/dhcpd-notify.sh
%{_bindir}/wifi-direct-server.sh
%{_bindir}/wifi-direct-dhcp.sh
%{_sbindir}/p2p_supp.sh
%attr(755,-,-) %{_bindir}/dhcpd-notify.sh
%attr(755,-,-) %{_bindir}/wifi-direct-server.sh
%attr(755,-,-) %{_bindir}/wifi-direct-dhcp.sh
%attr(755,-,-) %{TZ_SYS_RO_ETC}/wifi-direct/udhcp_script.non-autoip
%attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/*
%attr(644,root,root) %{_datadir}/dbus-1/system-services/*
%attr(755,-,-) %{_sbindir}/p2p_supp.sh

%files -n wifi-direct-plugin-wpasupplicant
%manifest wifi-direct-plugin-wpasupplicant.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_libdir}/wifi-direct-plugin-wpasupplicant.so
