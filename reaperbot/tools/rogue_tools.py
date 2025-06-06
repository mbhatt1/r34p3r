"""
Rogue Framework Tools

Integrated battle-tested tools from the Rogue AI-powered web vulnerability scanner.
Provides browser automation and code execution capabilities.

Based on the proven Rogue framework implementation.
"""

import asyncio
import sys
from io import StringIO
from typing import Dict, Any, Optional
from playwright.async_api import async_playwright, Page, Browser, BrowserContext

class RogueTools:
    """Browser automation and code execution tools from Rogue framework"""
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.playwright = None
    
    async def start_browser(self, headless: bool = True) -> bool:
        """Start browser instance"""
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=headless)
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()
            return True
        except Exception:
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
    
    async def execute_js(self, js_code: str) -> Dict[str, Any]:
        """Execute JavaScript code on the page"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            result = await self.page.evaluate(js_code)
            return {
                "success": True,
                "result": result,
                "html": await self.page.content()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def click(self, css_selector: str) -> Dict[str, Any]:
        """Click an element on the page"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.click(css_selector, timeout=5000)
            return {
                "success": True,
                "html": await self.page.content(),
                "url": self.page.url
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def fill(self, css_selector: str, value: str) -> Dict[str, Any]:
        """Fill a form field"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.fill(css_selector, value, timeout=5000)
            return {
                "success": True,
                "html": await self.page.content(),
                "selector": css_selector,
                "value": value
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def submit(self, css_selector: str) -> Dict[str, Any]:
        """Submit a form by clicking an element"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.locator(css_selector).click()
            return {
                "success": True,
                "html": await self.page.content(),
                "url": self.page.url
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def presskey(self, key: str) -> Dict[str, Any]:
        """Press a keyboard key"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.keyboard.press(key)
            return {
                "success": True,
                "html": await self.page.content(),
                "key": key
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def goto(self, url: str) -> Dict[str, Any]:
        """Navigate to a URL"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.goto(url)
            return {
                "success": True,
                "html": await self.page.content(),
                "url": self.page.url,
                "title": await self.page.title()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def refresh(self) -> Dict[str, Any]:
        """Refresh the current page"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.reload()
            return {
                "success": True,
                "html": await self.page.content(),
                "url": self.page.url
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def python_interpreter(self, code: str) -> Dict[str, Any]:
        """Execute Python code and capture output"""
        try:
            output_buffer = StringIO()
            old_stdout = sys.stdout
            sys.stdout = output_buffer
            
            try:
                exec(code)
                output = output_buffer.getvalue()
                return {
                    "success": True,
                    "output": output,
                    "code": code
                }
            finally:
                sys.stdout = old_stdout
                output_buffer.close()
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "code": code
            }
    
    async def get_page_source(self) -> Dict[str, Any]:
        """Get current page HTML source"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            return {
                "success": True,
                "html": await self.page.content(),
                "url": self.page.url,
                "title": await self.page.title()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_cookies(self) -> Dict[str, Any]:
        """Get all cookies from current context"""
        try:
            if not self.context:
                return {"success": False, "error": "Browser not started"}
            
            cookies = await self.context.cookies()
            return {
                "success": True,
                "cookies": cookies
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def set_cookie(self, name: str, value: str, domain: str = None, path: str = "/") -> Dict[str, Any]:
        """Set a cookie"""
        try:
            if not self.context:
                return {"success": False, "error": "Browser not started"}
            
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
            return {"success": False, "error": str(e)}
    
    async def wait_for_element(self, selector: str, timeout: int = 5000) -> Dict[str, Any]:
        """Wait for element to appear"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.wait_for_selector(selector, timeout=timeout)
            return {
                "success": True,
                "selector": selector,
                "html": await self.page.content()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_element_text(self, selector: str) -> Dict[str, Any]:
        """Get text content of element"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            text = await self.page.text_content(selector)
            return {
                "success": True,
                "selector": selector,
                "text": text
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_element_attribute(self, selector: str, attribute: str) -> Dict[str, Any]:
        """Get attribute value of element"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            value = await self.page.get_attribute(selector, attribute)
            return {
                "success": True,
                "selector": selector,
                "attribute": attribute,
                "value": value
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def screenshot(self, path: str = None, full_page: bool = True) -> Dict[str, Any]:
        """Take screenshot of current page"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
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
            return {"success": False, "error": str(e)}
    
    async def evaluate_expression(self, expression: str) -> Dict[str, Any]:
        """Evaluate JavaScript expression and return result"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            result = await self.page.evaluate(f"() => {expression}")
            return {
                "success": True,
                "expression": expression,
                "result": result
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def inject_script(self, script_content: str) -> Dict[str, Any]:
        """Inject JavaScript into the page"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            await self.page.add_script_tag(content=script_content)
            return {
                "success": True,
                "script": script_content
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def intercept_requests(self, url_pattern: str = "*") -> Dict[str, Any]:
        """Set up request interception"""
        try:
            if not self.page:
                return {"success": False, "error": "Browser not started"}
            
            intercepted_requests = []
            
            async def handle_request(request):
                intercepted_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data
                })
                await request.continue_()
            
            await self.page.route(url_pattern, handle_request)
            
            return {
                "success": True,
                "pattern": url_pattern,
                "intercepted_requests": intercepted_requests
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

# Utility functions for compatibility with existing agents
async def execute_js(js_code: str, tools_instance: RogueTools = None) -> Dict[str, Any]:
    """Execute JavaScript code"""
    if tools_instance:
        return await tools_instance.execute_js(js_code)
    
    tools = RogueTools()
    await tools.start_browser()
    try:
        result = await tools.execute_js(js_code)
        return result
    finally:
        await tools.stop_browser()

async def click_element(css_selector: str, tools_instance: RogueTools = None) -> Dict[str, Any]:
    """Click element by CSS selector"""
    if tools_instance:
        return await tools_instance.click(css_selector)
    
    tools = RogueTools()
    await tools.start_browser()
    try:
        result = await tools.click(css_selector)
        return result
    finally:
        await tools.stop_browser()

async def fill_form(css_selector: str, value: str, tools_instance: RogueTools = None) -> Dict[str, Any]:
    """Fill form field"""
    if tools_instance:
        return await tools_instance.fill(css_selector, value)
    
    tools = RogueTools()
    await tools.start_browser()
    try:
        result = await tools.fill(css_selector, value)
        return result
    finally:
        await tools.stop_browser()

async def navigate_to(url: str, tools_instance: RogueTools = None) -> Dict[str, Any]:
    """Navigate to URL"""
    if tools_instance:
        return await tools_instance.goto(url)
    
    tools = RogueTools()
    await tools.start_browser()
    try:
        result = await tools.goto(url)
        return result
    finally:
        await tools.stop_browser()

def execute_python_code(code: str) -> Dict[str, Any]:
    """Execute Python code"""
    tools = RogueTools()
    return tools.python_interpreter(code)