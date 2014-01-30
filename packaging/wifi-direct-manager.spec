Name:       wifi-direct-manager
Summary:    Wi-Fi Direct manger
Version:    1.0.0
Release:    1
Group:      Network & Connectivity/Wireless
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Requires(post): /usr/bin/vconftool
BuildRequires:  pkgconfig(wifi-direct)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  cmake


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

%ifarch %{arm}
export ARCH=arm
%else

%if 0%{?simulator}
export ARCH=emul
%else
export ARCH=i586
%endif

%endif

%cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCHITECTURE=$ARCH
#make %{?jobs:-j%jobs}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install
#%__strip %{buildroot}%{_libdir}/wifi-direct-plugin-wpasupplicant.so
#%__strip %{buildroot}%{_bindir}/wfd-manager

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}
cp %{_builddir}/%{buildsubdir}/LICENSE.APLv2 %{buildroot}/usr/share/license/wifi-direct-plugin-wpasupplicant

%post
chmod 644 /usr/etc/wifi-direct/dhcpd.p2p.conf
chmod 755 /usr/bin/dhcpd-notify.sh
chmod 755 /usr/etc/wifi-direct/udhcp_script.non-autoip
chmod 755 /usr/bin/wifi-direct-server.sh
chmod 755 /usr/bin/wifi-direct-dhcp.sh
chmod 755 /usr/sbin/p2p_supp.sh

vconftool set -t int memory/wifi_direct/state 0 -u 5000 -i -f
vconftool set -t int memory/private/wifi_direct_manager/dhcp_ip_lease 0 -i -f
vconftool set -t string memory/private/wifi_direct_manager/dhcpc_server_ip 0.0.0.0 -i -f

%postun

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_bindir}/wfd-manager
/usr/etc/wifi-direct/dhcpd.p2p.conf
/usr/etc/wifi-direct/udhcp_script.non-autoip
/usr/etc/wifi-direct/p2p_supp.conf
%{_bindir}/dhcpd-notify.sh
%{_bindir}/wifi-direct-server.sh
%{_bindir}/wifi-direct-dhcp.sh
%{_sbindir}/p2p_supp.sh
%attr(755,-,-) %{_bindir}/dhcpd-notify.sh
%attr(755,-,-) %{_bindir}/wifi-direct-server.sh
%attr(755,-,-) %{_bindir}/wifi-direct-dhcp.sh
%attr(755,-,-) /usr/etc/wifi-direct/udhcp_script.non-autoip
%attr(755,-,-) %{_sbindir}/p2p_supp.sh
/usr/share/license/%{name}

%files -n wifi-direct-plugin-wpasupplicant
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/wifi-direct-plugin-wpasupplicant.so
/usr/share/license/wifi-direct-plugin-wpasupplicant

