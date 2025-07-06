#!/usr/bin/env python3
"""
Test script to verify agents API and simulate browser behavior
"""

import requests
import json

def test_agents_api():
    """Test the agents API endpoint"""
    try:
        print("Testing agents API...")
        response = requests.get('http://localhost:5000/api/agents')
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            agents = response.json()
            print(f"Number of agents: {len(agents)}")
            print("\nAgents:")
            for agent_id, agent_data in agents.items():
                print(f"  {agent_id}: {agent_data['name']} - {agent_data['status']}")
            return True
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Error testing agents API: {e}")
        return False

def test_main_page():
    """Test the main page"""
    try:
        print("\nTesting main page...")
        response = requests.get('http://localhost:5000/')
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            content = response.text
            # Check for key elements
            if 'agentsGrid' in content:
                print("✓ agentsGrid element found")
            else:
                print("✗ agentsGrid element NOT found")
                
            if 'CybersecuritySuite' in content:
                print("✓ CybersecuritySuite class found")
            else:
                print("✗ CybersecuritySuite class NOT found")
                
            if 'loadAgents' in content:
                print("✓ loadAgents function found")
            else:
                print("✗ loadAgents function NOT found")
                
            return True
        else:
            print(f"Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error testing main page: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing Intratech Cybersecurity Suite...")
    
    # Test agents API
    api_ok = test_agents_api()
    
    # Test main page
    page_ok = test_main_page()
    
    if api_ok and page_ok:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")