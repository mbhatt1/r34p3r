"""
Browser Automation Tools

Integrated browser automation tools from Rogue and VibePenTester frameworks.
Provides comprehensive browser interaction capabilities for security testing.
"""

import asyncio
import time
from typing import Dict, Any, List, Optional
from playwright.async_api import async_playwright, Page, Browser, BrowserContext

class BrowserAutomationTools:
    """Comprehensive browser automation tools for security testing"""
    
    def __init__(self):
        """Initialize browser automation tools"""
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.playwright = None
    
    async def start_browser(self, headless: bool = True, browser_type: str = "chromium") -> bool:
        """Start browser instance"""
        try:
            self.playwright = await async_playwright().start()
            
            if browser_type == "chromium":
                self.browser = await self.playwright.chromium.launch(headless=headless)
            elif browser_type == "firefox":
                self.browser = await self.playwright.firefox.launch(headless=headless)
            elif browser_type == "webkit":
                self.browser = await self.playwright.webkit.launch(headless=headless)
            else:
                raise ValueError(f"Unsupported browser type: {browser_type}")
            
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()
            
            return True
        except Exception as e:
            return False
    
    async def stop_browser(self):
        """Stop browser instance"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception:
            pass
    
    async def goto(self, url: str, timeout: int = 30000) -> Dict[str, Any]:
        """Navigate to URL"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            response = await self.page.goto(url, timeout=timeout)
            
            return {
                "success": True,
                "url": self.page.url,
                "status": response.status if response else None,
                "title": await self.page.title(),
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def click(self, selector: str, timeout: int = 5000) -> Dict[str, Any]:
        """Click element by selector"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.click(selector, timeout=timeout)
            
            return {
                "success": True,
                "url": self.page.url,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def fill(self, selector: str, value: str, timeout: int = 5000) -> Dict[str, Any]:
        """Fill input field"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.fill(selector, value, timeout=timeout)
            
            return {
                "success": True,
                "selector": selector,
                "value": value,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def submit_form(self, form_selector: str = "form", timeout: int = 5000) -> Dict[str, Any]:
        """Submit form"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            # Try to find submit button first
            submit_selectors = [
                f"{form_selector} input[type='submit']",
                f"{form_selector} button[type='submit']",
                f"{form_selector} button",
                f"{form_selector} input[type='button']"
            ]
            
            for selector in submit_selectors:
                try:
                    await self.page.click(selector, timeout=1000)
                    break
                except:
                    continue
            else:
                # If no submit button found, try pressing Enter
                await self.page.press(form_selector, "Enter")
            
            # Wait for navigation or response
            await self.page.wait_for_load_state("networkidle", timeout=timeout)
            
            return {
                "success": True,
                "url": self.page.url,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute_js(self, js_code: str) -> Dict[str, Any]:
        """Execute JavaScript code"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            result = await self.page.evaluate(js_code)
            
            return {
                "success": True,
                "result": result,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_cookies(self) -> Dict[str, Any]:
        """Get all cookies"""
        try:
            if not self.context:
                raise Exception("Browser not started")
            
            cookies = await self.context.cookies()
            
            return {
                "success": True,
                "cookies": cookies
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def set_cookie(self, name: str, value: str, domain: str = None, path: str = "/") -> Dict[str, Any]:
        """Set cookie"""
        try:
            if not self.context:
                raise Exception("Browser not started")
            
            cookie = {
                "name": name,
                "value": value,
                "path": path
            }
            
            if domain:
                cookie["domain"] = domain
            else:
                cookie["url"] = self.page.url
            
            await self.context.add_cookies([cookie])
            
            return {
                "success": True,
                "cookie": cookie
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def wait_for_element(self, selector: str, timeout: int = 5000) -> Dict[str, Any]:
        """Wait for element to appear"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.wait_for_selector(selector, timeout=timeout)
            
            return {
                "success": True,
                "selector": selector,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_element_text(self, selector: str) -> Dict[str, Any]:
        """Get text content of element"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            text = await self.page.text_content(selector)
            
            return {
                "success": True,
                "selector": selector,
                "text": text
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_element_attribute(self, selector: str, attribute: str) -> Dict[str, Any]:
        """Get attribute value of element"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            value = await self.page.get_attribute(selector, attribute)
            
            return {
                "success": True,
                "selector": selector,
                "attribute": attribute,
                "value": value
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def screenshot(self, path: str = None, full_page: bool = True) -> Dict[str, Any]:
        """Take screenshot"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            screenshot_bytes = await self.page.screenshot(
                path=path,
                full_page=full_page
            )
            
            return {
                "success": True,
                "path": path,
                "bytes": screenshot_bytes if not path else None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_page_source(self) -> Dict[str, Any]:
        """Get page HTML source"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            html = await self.page.content()
            
            return {
                "success": True,
                "html": html,
                "url": self.page.url,
                "title": await self.page.title()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def refresh_page(self) -> Dict[str, Any]:
        """Refresh current page"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.reload()
            
            return {
                "success": True,
                "url": self.page.url,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def press_key(self, key: str, selector: str = "body") -> Dict[str, Any]:
        """Press keyboard key"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.press(selector, key)
            
            return {
                "success": True,
                "key": key,
                "selector": selector
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def hover(self, selector: str, timeout: int = 5000) -> Dict[str, Any]:
        """Hover over element"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            await self.page.hover(selector, timeout=timeout)
            
            return {
                "success": True,
                "selector": selector,
                "html": await self.page.content()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def select_option(self, selector: str, value: str = None, label: str = None) -> Dict[str, Any]:
        """Select option from dropdown"""
        try:
            if not self.page:
                raise Exception("Browser not started")
            
            if value:
                await self.page.select_option(selector, value=value)
            elif label:
                await self.page.select_option(selector, label=label)
            else:
                raise Exception("Either value or label must be provided")
            
            return {
                "success": True,
                "selector": selector,
                "value": value,
                "label": label
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }