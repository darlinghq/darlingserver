/**
 * This file is part of Darling.
 *
 * Copyright (C) 2026 Lubos Dolezel
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DARLINGSERVER_PREFIX_SETUP_HPP_
#define _DARLINGSERVER_PREFIX_SETUP_HPP_

#include <string_view>

// Helpers for the part of darlingserver's startup that runs as root and assembles the user's prefix.
// They hold no state, so that they can be tested on the host as an ordinary user.
namespace DarlingServer::PrefixSetup {
	// Whether a path can be written into an overlayfs or fuse-overlayfs mount option string as it is.
	// Both parsers split options at ',' and lower layers at ':', and treat '\' as an escape; how
	// escapes are undone differs between kernel versions and fuse-overlayfs, so such paths are
	// refused rather than escaped. Control characters are refused too, and so is anything but an
	// absolute path.
	bool isPlainOptionPath(std::string_view path);
};

#endif // _DARLINGSERVER_PREFIX_SETUP_HPP_
