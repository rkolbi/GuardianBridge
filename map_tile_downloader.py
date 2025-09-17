# GuardianBridge - A Meshtastic Gateway for Community Resilience
# Copyright (C) 2025 Robert Kolbasowski
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# map_tile_downloader.py

import os
import math
import requests
import time
import settings

# --- CONFIGURATION ---
RADIUS_MILES = 10
# Define the zoom levels you want to download. 10=Region, 14=Town, 16=Street level
ZOOM_LEVELS = range(10, 17) 
# The web directory where the map tiles will be served from.
# This path should be relative to your web server's root.
WEB_DIRECTORY_PATH = "/var/www" # Standard for Apache on Debian/Ubuntu
TILE_STORAGE_DIR = os.path.join(WEB_DIRECTORY_PATH, "map-items", "map-tiles")

# --- OpenStreetMap Tile Server URL ---
# {s} is the subdomain (a,b,c), {z} is zoom, {x} is x-tile, {y} is y-tile
TILE_SERVER_URL = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
# Be a good internet citizen.
REQUEST_HEADERS = {
    "User-Agent": "GuardianBridge-Tile-Downloader/1.0 (for offline caching)"
}

# --- HELPER FUNCTIONS ---

def deg_to_tile(lat_deg, lon_deg, zoom):
    """Converts lat/lon to tile numbers"""
    lat_rad = math.radians(lat_deg)
    n = 2.0 ** zoom
    xtile = int((lon_deg + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
    return (xtile, ytile)

def calculate_bounding_box(lat_deg, lon_deg, radius_miles):
    """Calculate a bounding box `radius_miles` from a center point."""
    lat_rad = math.radians(lat_deg)
    # Earth's radius in miles
    earth_radius = 3958.8 
    
    # Angular radius in radians
    angular_radius = radius_miles / earth_radius
    
    lat_delta = math.degrees(angular_radius)
    lon_delta = math.degrees(angular_radius / math.cos(lat_rad))
    
    min_lat = lat_deg - lat_delta
    max_lat = lat_deg + lat_delta
    min_lon = lon_deg - lon_delta
    max_lon = lon_deg + lon_delta
    
    return (min_lat, max_lat, min_lon, max_lon)


if __name__ == "__main__":
    print("--- GuardianBridge Offline Map Tile Downloader ---")
    
    center_lat = settings.LATITUDE
    center_lon = settings.LONGITUDE

    if not center_lat or not center_lon:
        print("ERROR: LATITUDE and LONGITUDE must be set in your .env file.")
        exit(1)

    print(f"Center Point: Latitude={center_lat}, Longitude={center_lon}")
    print(f"Download Radius: {RADIUS_MILES} miles")
    print(f"Zoom Levels: {list(ZOOM_LEVELS)}")
    print(f"Output Directory: {TILE_STORAGE_DIR}")
    print("-" * 50)

    if not os.path.exists(WEB_DIRECTORY_PATH):
        print(f"ERROR: The specified web directory '{WEB_DIRECTORY_PATH}' does not exist.")
        print("Please check the `WEB_DIRECTORY_PATH` variable in this script.")
        exit(1)

    os.makedirs(TILE_STORAGE_DIR, exist_ok=True)

    min_lat, max_lat, min_lon, max_lon = calculate_bounding_box(center_lat, center_lon, RADIUS_MILES)
    total_tiles_to_download = 0
    tile_queue = []

    # First, calculate all tiles to download
    for zoom in ZOOM_LEVELS:
        min_x, min_y = deg_to_tile(max_lat, min_lon, zoom)
        max_x, max_y = deg_to_tile(min_lat, max_lon, zoom)
        
        for x in range(min_x, max_x + 1):
            for y in range(min_y, max_y + 1):
                tile_queue.append((zoom, x, y))
                total_tiles_to_download += 1

    print(f"Calculated {total_tiles_to_download} total tiles to download. This may take a while.")
    
    # Now, download the tiles
    downloaded_count = 0
    for zoom, x, y in tile_queue:
        # Construct local path
        z_str, x_str = str(zoom), str(x)
        output_path = os.path.join(TILE_STORAGE_DIR, z_str, x_str)
        os.makedirs(output_path, exist_ok=True)
        tile_path = os.path.join(output_path, f"{y}.png")

        downloaded_count += 1
        
        if os.path.exists(tile_path):
            print(f"[{downloaded_count}/{total_tiles_to_download}] SKIPPING {z_str}/{x_str}/{y}.png (already exists)")
            continue

        # Construct URL and download
        # Cycle through subdomains a, b, c
        subdomain = ['a', 'b', 'c'][(x + y) % 3] 
        url = TILE_SERVER_URL.format(s=subdomain, z=zoom, x=x, y=y)
        
        try:
            print(f"[{downloaded_count}/{total_tiles_to_download}] GET {url} -> {tile_path}")
            response = requests.get(url, headers=REQUEST_HEADERS, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes

            with open(tile_path, 'wb') as f:
                f.write(response.content)
            
            # Be polite to the tile server
            time.sleep(0.1)

        except requests.exceptions.RequestException as e:
            print(f"  -> ERROR downloading {url}: {e}")
            # If a tile fails, just continue to the next
            continue
    
    print("-" * 50)
    print("Download complete!")
    print(f"Map tiles are saved in {TILE_STORAGE_DIR}")
