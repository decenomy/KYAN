
Debian
====================
This directory contains files used to package kyanited/kyanite-qt
for Debian-based Linux systems. If you compile kyanited/kyanite-qt yourself, there are some useful files here.

## pivx: URI support ##


kyanite-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install kyanite-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your kyanite-qt binary to `/usr/bin`
and the `../../share/pixmaps/pivx128.png` to `/usr/share/pixmaps`

kyanite-qt.protocol (KDE)

