# Troubleshooting Interactive Topology Graph

## Issue: Nodes Not Appearing After Expansion

### Quick Fix - Check Browser Console

1. **Open Browser Developer Tools**
   - Chrome/Edge: Press `F12` or `Ctrl+Shift+I` (Windows) / `Cmd+Option+I` (Mac)
   - Firefox: Press `F12` or `Ctrl+Shift+K`
   - Safari: Enable Developer Menu in Preferences, then press `Cmd+Option+C`

2. **Click the "Console" tab**

3. **Click a node and then "Discover Neighbors"**

4. **Look for these messages:**
   ```
   API Response: {success: true, root: {...}, neighbors: [...], ...}
   Expanding node: 10.1.1.1 with 5 neighbors
   Adding neighbor: 10.1.1.2
   ✓ Added neighbor node: 10.1.1.2
   ✓ Added edge: 10.1.1.1-10.1.1.2
   Running layout...
   ```

### Common Issues and Solutions

#### 1. "API Response shows `neighbors: []`"
**Problem**: The device has no neighbors or CDP/LLDP is not working

**Check**:
- Does the device actually have neighbors?
- Is CDP/LLDP enabled on the device?
- Try running `show cdp neighbors detail` manually on the device

**Solution**: This is normal if device has no downstream neighbors

---

#### 2. "API Response shows error"
**Problem**: Cannot connect to device or authentication failed

**Example errors**:
- `"Connection refused"`
- `"Authentication failed"`
- `"Timeout"`

**Check**:
- Are the credentials correct?
- Is the device reachable from the server?
- Is SSH enabled on the device?
- Try SSH manually: `ssh username@device_ip`

**Solution**:
- Verify credentials
- Check network connectivity
- Ensure SSH is enabled

---

#### 3. "Neighbors array has data but nodes don't appear"
**Problem**: JavaScript error or Cytoscape issue

**Check Console for**:
- Red error messages
- JavaScript exceptions
- Failed to add node/edge messages

**Look for**:
```
Adding neighbor: undefined
```
This means `neighbor.remote_ip` and `neighbor.remote_name` are both empty.

**Solution**: This is a data issue - neighbor has no identifying information

---

#### 4. "Console shows '✓ Added neighbor node' but I don't see it"
**Problem**: Node is added but outside viewport or layout failed

**Solutions**:
1. Click **"Fit to View"** button in left sidebar
2. Click **"Refresh Layout"** button
3. Zoom out with mouse wheel
4. Check node count in stats - does it increase?

---

#### 5. "Toast says 'Discovered X neighbors' but graph unchanged"
**Problem**: Nodes might be hidden or overlapping

**Try**:
1. Click "Fit to View"
2. Drag the canvas around
3. Zoom out completely
4. Click "Refresh Layout"

**Check**:
- Look at node count stat - did it increase?
- Look at edge count stat - did it increase?

---

### Debug Mode - Additional Logging

If you want even more debugging, open browser console and run:

```javascript
// See all current nodes
console.log('Current nodes:', cy.nodes().map(n => n.id()));

// See all current edges
console.log('Current edges:', cy.edges().map(e => e.id()));

// Get graph as JSON
console.log('Graph data:', cy.json());
```

---

### Expected Console Output (Success)

When everything works correctly, you should see:

```
API Response: {
  success: true,
  root: {
    ip_address: "10.1.1.1",
    caption: "core-switch",
    vendor: "Cisco",
    ...
  },
  neighbors: [
    {
      local_interface: "GigabitEthernet1/0/1",
      remote_name: "dist-switch-1",
      remote_ip: "10.1.1.2",
      remote_port: "GigabitEthernet1/0/24",
      ...
    },
    ...
  ]
}
Expanding node: 10.1.1.1 with 3 neighbors
Adding neighbor: 10.1.1.2
✓ Added neighbor node: 10.1.1.2
✓ Added edge: 10.1.1.1-10.1.1.2
Adding neighbor: 10.1.1.3
✓ Added neighbor node: 10.1.1.3
✓ Added edge: 10.1.1.1-10.1.1.3
Adding neighbor: 10.1.1.4
✓ Added neighbor node: 10.1.1.4
✓ Added edge: 10.1.1.1-10.1.1.4
Running layout...
```

And in the graph:
- Node count increases by 3
- Edge count increases by 3
- Layout animates
- New nodes appear connected to expanded node

---

### Testing the API Directly

You can test the API endpoint directly in browser console:

```javascript
fetch('/api/topology/discover', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    target: '10.1.1.1',
    username: 'admin',
    password: 'your-password',
    secret: 'enable-secret',
    vendor_mode: 'auto'
  })
})
.then(r => r.json())
.then(data => console.log('Direct API test:', data));
```

---

### Still Not Working?

1. **Refresh the page** and try again
2. **Check credentials** are correct
3. **Verify device is reachable** from NOC Toolkit server
4. **Try a different device** to see if it's device-specific
5. **Check server logs** for Python errors
6. **Share console output** with admin for further debugging

---

## Common Scenarios

### Scenario 1: First node shows, expansions don't
**Likely cause**: Credentials not being passed correctly

**Fix**: Check browser console for API response errors

### Scenario 2: Some neighbors appear, others don't
**Likely cause**: Some neighbors missing IP address or name

**Fix**: Check console - neighbors without `remote_ip` or `remote_name` are skipped

### Scenario 3: Graph freezes after clicking expand
**Likely cause**: JavaScript error

**Fix**: Check console for red error messages

### Scenario 4: Layout looks messy
**Not a bug**: Force-directed layouts can be chaotic with many nodes

**Fix**: Click "Refresh Layout" multiple times or manually drag nodes

---

## Files to Check

If issues persist, check these files:

1. **[templates/topology_graph.html](templates/topology_graph.html:711-789)** - Expansion logic with console logs
2. **[app.py](app.py:2243-2293)** - API endpoint that fetches topology
3. **Server console** - Python errors will show here
4. **Browser console** - JavaScript errors show here

---

## Contact/Report

If you find a bug:
1. **Capture browser console output** (screenshot or copy/paste)
2. **Note the device IP/hostname** you were trying to expand
3. **Check server logs** for Python errors
4. **Document the steps** to reproduce

This will help debug the issue quickly!
