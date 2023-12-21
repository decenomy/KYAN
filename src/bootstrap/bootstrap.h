#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <cerrno>  // For perror
#include <cstring>  // For strerror
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <sys/stat.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "minizip/unzip.h"

#ifndef TICKER
#define TICKER "KYAN"
#endif

class BOOTSTRAP{

public:

	static bool rmDirectory(const std::string& path);
	static bool isDirectory(const std::string& path);
	static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
	static bool DownloadFile(const std::string& url, const std::string& outputFileName);
	static bool extractZip(const std::string& inputPath, const std::string& outputPath);

private:

	static bool ensureOutputFolder(const std::string& outputPath);
	static bool endsWithSlash(const std::string& str);
};

#endif
