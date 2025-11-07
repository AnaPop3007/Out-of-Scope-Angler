# Out of scope: DNS Dashboard

A retro-tech themed dashboard for visualizing DNS connections, simulated packets, and link checks.  
Currently implemented as a **frontend prototype** with simulated data.

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Technologies](#technologies)
- [File Structure](#file-structure)
- [Usage](#usage)
- [Future Work](#future-work)

## Description

This project is a part of a hackathon setup for monitoring DNS activity and connections.  
The current version focuses on **frontend features**, including:

- Link input and connection cards
- DNS packet sidebar simulation
- Retro-tech style interface
- Basic navbar for page navigation

Data is currently **simulated**, with placeholders for backend integration.

## Features

- **Navbar**: Navigation between Home, Map, Connections, and Stats.
- **Link Checker**: Input a link, click "Check" or press Enter to simulate a new connection.
- **Connection Cards**: Show simulated connection info (IP, status, packet count).
- **DNS Packets Sidebar**: Simulated DNS packets added automatically every 5 seconds.
- **Retro-Tech Theme**: Dark UI with neon-cyan and magenta accents, monospace font.
- **Responsive Layout**: Sidebar and main content layout using Tailwind CSS.

## Technologies

- HTML5
- CSS3 + Tailwind CSS
- Vanilla JavaScript
- Leaflet.js (for map visualization placeholder)

## File Structure

frontend/
├─ images/
│ └─ logo.png # Project logo for favicon and navbar
├─ style.css # Custom CSS styling
├─ index.html # Main page with link input & connection cards
├─ harta.html # Placeholder for DNS map page
└─ README.md # This file

## Usage

1. Open `index.html` in a browser.
2. Enter a URL in the input field and press **Enter** or click **Check**.
3. New connection cards appear in the main area.
4. DNS packets appear in the sidebar automatically every 5 seconds.

## Future Work

- Integrate real-time backend data for connections and DNS packets.
- Implement map visualization on `harta.html` using Leaflet and real IP geolocation.
- Add CTF challenges and interactive packet analysis.
- Enhance animations and interactivity for new packets and connection cards.
- Add authentication, API integration, and persistent storage.

---

