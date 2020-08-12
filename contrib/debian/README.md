
Debian
====================
This directory contains files used to package kyand/kyan-qt
for Debian-based Linux systems. If you compile kyand/kyan-qt yourself, there are some useful files here.

## kyan: URI support ##


kyan-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install kyan-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your kyan-qt binary to `/usr/bin`
and the `../../share/pixmaps/kyan128.png` to `/usr/share/pixmaps`

kyan-qt.protocol (KDE)

