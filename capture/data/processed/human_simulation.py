from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import NoSuchElementException, TimeoutException
import random
import time
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HumanTrafficSimulator:
    def __init__(self, headless=False):
        """Initialize the simulator with options to be visible or headless."""
        self.options = webdriver.ChromeOptions()
        
        # Add user agent that looks like a regular browser
        self.options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
        
        # Optional headless mode
        if headless:
            self.options.add_argument("--headless")
        
        # Disable automation flags to avoid detection
        self.options.add_argument("--disable-blink-features=AutomationControlled")
        self.options.add_experimental_option("excludeSwitches", ["enable-automation"])
        self.options.add_experimental_option("useAutomationExtension", False)
        
        self.driver = webdriver.Chrome(options=self.options)
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        self.action = ActionChains(self.driver)
        
        # Set a realistic window size
        self.driver.set_window_size(1366, 768)
        
    def human_like_delay(self, min_seconds=1, max_seconds=5):
        """Wait for a random amount of time to simulate human behavior."""
        delay = random.uniform(min_seconds, max_seconds)
        time.sleep(delay)
        
    def move_mouse_randomly(self, num_moves=3):
        """Move the mouse cursor in a human-like pattern."""
        viewport_width = self.driver.execute_script("return window.innerWidth;")
        viewport_height = self.driver.execute_script("return window.innerHeight;")
        
        for _ in range(num_moves):
            # Generate random x, y coordinates within the viewport
            x = random.randint(10, viewport_width - 10)
            y = random.randint(10, viewport_height - 10)
            
            # Create a smoother mouse movement by adding intermediate points
            current_pos = self.action.w3c_actions.pointer_action.source.create_pointer_move(
                0, 0, 0
            )
            
            # Move with a natural easing function
            steps = random.randint(5, 15)
            for step in range(1, steps + 1):
                progress = step / steps
                # Ease in-out function for more natural movement
                eased_progress = 0.5 - 0.5 * math.cos(progress * math.pi)
                
                move_x = int(x * eased_progress)
                move_y = int(y * eased_progress)
                
                self.action.move_by_offset(move_x, move_y)
                self.action.pause(random.uniform(0.01, 0.05))
                
            self.action.perform()
            self.human_like_delay(0.5, 2)
    
    def scroll_page(self, direction="down"):
        """Scroll the page in a human-like way."""
        viewport_height = self.driver.execute_script("return window.innerHeight;")
        
        # Get total document height
        doc_height = self.driver.execute_script("return document.body.scrollHeight;")
        current_position = self.driver.execute_script("return window.pageYOffset;")
        
        if direction == "down":
            # Don't scroll beyond the document height
            max_scroll = min(doc_height - viewport_height - current_position, viewport_height)
            if max_scroll <= 0:
                return
                
            # Scroll down with variable speed
            scroll_amount = random.randint(int(viewport_height/4), int(viewport_height/2))
            
            # Smooth scrolling with multiple small steps
            steps = random.randint(5, 15)
            for step in range(1, steps + 1):
                scroll_step = int((scroll_amount * step) / steps)
                self.driver.execute_script(f"window.scrollBy(0, {scroll_step});")
                time.sleep(random.uniform(0.05, 0.2))
            
        else:  # scroll up
            if current_position <= 0:
                return
                
            # Scroll up with variable speed
            scroll_amount = -random.randint(int(viewport_height/4), int(viewport_height/2))
            
            # Smooth scrolling with multiple small steps
            steps = random.randint(5, 15)
            for step in range(1, steps + 1):
                scroll_step = int((scroll_amount * step) / steps)
                self.driver.execute_script(f"window.scrollBy(0, {scroll_step});")
                time.sleep(random.uniform(0.05, 0.2))
        
        self.human_like_delay(1, 3)
    
    def find_and_click_link(self):
        """Find a random link on the page and click it."""
        try:
            # Get all links on the page
            links = self.driver.find_elements(By.TAG_NAME, "a")
            
            # Filter out links that are likely navigation, social media, etc.
            content_links = []
            for link in links:
                href = link.get_attribute("href")
                
                # Skip empty links, javascript calls, or off-site links
                if not href or href.startswith("javascript:") or href == "#":
                    continue
                    
                # Try to prioritize links that are within the same domain
                current_domain = self.driver.current_url.split("//")[-1].split("/")[0]
                if current_domain in href:
                    content_links.append(link)
            
            # If we found valid links, click a random one
            if content_links:
                random_link = random.choice(content_links)
                
                # Scroll the link into view with some margin
                self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", random_link)
                self.human_like_delay(1, 2)
                
                # Move mouse to link and click
                self.action.move_to_element(random_link)
                self.action.pause(random.uniform(0.3, 1))
                self.action.click()
                self.action.perform()
                return True
            
            return False
        
        except (NoSuchElementException, TimeoutException) as e:
            logger.warning(f"Error finding or clicking link: {e}")
            return False
    
    def type_in_search_box(self, search_terms=["product", "information", "help", "guide", "review"]):
        """Find a search box and type a query with human-like typing."""
        try:
            # Try to find search input
            search_inputs = self.driver.find_elements(By.XPATH, 
                "//input[contains(@type, 'search') or contains(@name, 'search') or contains(@id, 'search') or contains(@class, 'search')]")
            
            if not search_inputs:
                return False
                
            search_input = search_inputs[0]
            search_term = random.choice(search_terms)
            
            # Make search input visible
            self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", search_input)
            self.human_like_delay(0.5, 1.5)
            
            # Click on the search box
            self.action.move_to_element(search_input)
            self.action.click()
            self.action.perform()
            self.human_like_delay(0.5, 1)
            
            # Type with human-like delays between keystrokes
            for char in search_term:
                search_input.send_keys(char)
                time.sleep(random.uniform(0.05, 0.25))
            
            self.human_like_delay(0.5, 1.5)
            
            # Press Enter to search
            search_input.submit()
            return True
            
        except (NoSuchElementException, TimeoutException) as e:
            logger.warning(f"Error with search box: {e}")
            return False
    
    def navigate_to_url(self, url):
        """Navigate to a specific URL with human-like behavior."""
        try:
            logger.info(f"Navigating to {url}")
            self.driver.get(url)
            self.human_like_delay(2, 5)  # Wait for page to load
            
            # Simulate a human looking at the page
            self.scroll_page("down")
            self.human_like_delay(1, 3)
            
            # Maybe scroll back up
            if random.random() < 0.3:
                self.scroll_page("up")
                
            return True
        except Exception as e:
            logger.error(f"Error navigating to {url}: {e}")
            return False
    
    def simulate_browsing_session(self, start_urls, session_duration=300):
        """
        Simulate a complete browsing session with human-like behavior.
        
        Args:
            start_urls (list): List of URLs to start the browsing from
            session_duration (int): Duration of the session in seconds
        """
        try:
            start_time = time.time()
            
            # Start with a random URL from the provided list
            current_url = random.choice(start_urls)
            self.navigate_to_url(current_url)
            
            # Track visited pages to avoid loops
            visited_pages = [current_url]
            
            while time.time() - start_time < session_duration:
                # Perform various human-like actions
                
                # 70% chance of scrolling
                if random.random() < 0.7:
                    scroll_direction = "down" if random.random() < 0.8 else "up"
                    self.scroll_page(scroll_direction)
                
                # 30% chance of clicking a link if we've been on this page for a while
                page_time = random.uniform(5, 20)  # Time to spend on each page
                if time.time() - start_time > page_time and random.random() < 0.3:
                    if self.find_and_click_link():
                        # Keep track of the new URL
                        current_url = self.driver.current_url
                        if current_url not in visited_pages:
                            visited_pages.append(current_url)
                            logger.info(f"Clicked link and navigated to: {current_url}")
                        
                        # Wait for page to load
                        self.human_like_delay(2, 5)
                
                # 10% chance of using search
                if random.random() < 0.1:
                    if self.type_in_search_box():
                        logger.info("Used search functionality")
                        # Wait for search results
                        self.human_like_delay(2, 4)
                        
                        # Update current URL
                        current_url = self.driver.current_url
                        if current_url not in visited_pages:
                            visited_pages.append(current_url)
                
                # If we've been browsing for a while, 10% chance to go back to a previous page
                if len(visited_pages) > 1 and random.random() < 0.1:
                    self.driver.back()
                    logger.info("Navigated back to previous page")
                    self.human_like_delay(1, 3)
                
                # Occasionally (5% chance), move the mouse randomly
                if random.random() < 0.05:
                    self.move_mouse_randomly()
                
                # If we haven't navigated in a while, go to a new start URL
                if random.random() < 0.05:
                    current_url = random.choice(start_urls)
                    self.navigate_to_url(current_url)
                    if current_url not in visited_pages:
                        visited_pages.append(current_url)
                        
            logger.info(f"Browsing session completed. Visited {len(visited_pages)} pages.")
            
        except Exception as e:
            logger.error(f"Error during browsing session: {e}")
        finally:
            self.close()
    
    def close(self):
        """Close the browser and clean up."""
        if hasattr(self, 'driver'):
            self.driver.quit()
            logger.info("Browser closed")

if __name__ == "__main__":
    # Import math module for easing function
    import math
    
    # List of starting URLs - replace with your target websites
    start_urls = [
        "https://www.example.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.reddit.com",
        "https://news.ycombinator.com"
    ]
    
    # Duration of each session in seconds (5 minutes)
    session_duration = 300
    
    # Number of sessions to run
    num_sessions = 3
    
    # Run multiple sessions
    for session in range(num_sessions):
        logger.info(f"Starting browsing session {session+1}/{num_sessions}")
        simulator = HumanTrafficSimulator(headless=False)  # Set to True to run in headless mode
        simulator.simulate_browsing_session(start_urls, session_duration)
        
        # Wait between sessions
        if session < num_sessions - 1:
            wait_time = random.uniform(60, 180)
            logger.info(f"Waiting {wait_time:.1f} seconds before next session")
            time.sleep(wait_time)