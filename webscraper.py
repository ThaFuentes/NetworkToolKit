import requests
from bs4 import BeautifulSoup
import json


def scrape_table(website):
    response = requests.get(website)
    content_set = set()  # Use a set to track unique values
    result = {"CONTENT": []}

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Finding the table, you might need to add specific attributes to find the correct table
        table = soup.find('table')

        if table:
            rows = table.find_all('tr')
            for row in rows:
                columns = row.find_all('td')  # change to 'th' if the row contains header cells
                row_data = [col.get_text().strip() for col in columns]
                sixth_value = get_sixth_value(row_data)
                if sixth_value and sixth_value.lower() != "none" and sixth_value not in content_set:
                    content_set.add(sixth_value)
                    result["CONTENT"].append(sixth_value)
        else:
            print(f"No table found on {website}")

    else:
        print(f"Failed to scrape {website}, status code: {response.status_code}")

    return result


def get_sixth_value(data):
    if len(data) > 5:
        return data[5]
    else:
        print("Data does not have six comma-separated values.")
        return None


website = input("Please enter the website URL: ")
result = scrape_table(website)

# Saving to a JSON file
with open('scraped_data.json', 'w') as json_file:
    json.dump(result, json_file)

print("Scraping completed, and data has been saved to scraped_data.json")
