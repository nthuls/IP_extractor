from selenium import webdriver
import re
import time


def extract_coordinates_from_url(url):
    """Extract the estimated coordinates from a given Google Maps URL."""
    match = re.search(r"@(-?\d+\.\d+),(-?\d+\.\d+)", url)
    if match:
        latitude = float(match.group(1))
        longitude = float(match.group(2))
        return latitude, longitude
    return None


def get_corrected_location():
    # Set up Chrome driver options for headless browsing
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")

    # Retrieve estimated coordinates from Google Maps
    with webdriver.Chrome(options=options) as driver:
        driver.get("https://www.google.com/maps")
        # Give the browser some time to fetch the location and load the URL
        time.sleep(10)
        estimated_url = driver.current_url

    estimated_coords = extract_coordinates_from_url(estimated_url)
    if not estimated_coords:
        print("Couldn't extract coordinates from URL.")
        return

    # Apply the correction
    latitude_difference = 0.0044278
    longitude_difference = -0.0058036
    corrected_latitude = estimated_coords[0] + latitude_difference
    corrected_longitude = estimated_coords[1] + longitude_difference

    # Print both the estimated and corrected values
    print(f"Estimated Location: Latitude: {estimated_coords[0]}, Longitude: {estimated_coords[1]}")
    print(f"Corrected Location: Latitude: {corrected_latitude}, Longitude: {corrected_longitude}")


# Run the function
get_corrected_location()
