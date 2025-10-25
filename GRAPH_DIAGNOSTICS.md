# Graph Diagnostics - Run in Browser Console

## Quick Diagnostic Check

Open the browser console (F12) and paste this:

```javascript
// Diagnostic script
console.log('=== GRAPH DIAGNOSTICS ===');
console.log('Cytoscape exists:', typeof cy !== 'undefined');
console.log('Total nodes:', cy.nodes().length);
console.log('Total edges:', cy.edges().length);
console.log('Node IDs:', cy.nodes().map(n => n.id()));
console.log('Edge IDs:', cy.edges().map(e => e.id()));
console.log('Viewport zoom:', cy.zoom());
console.log('Viewport pan:', cy.pan());
console.log('Container dimensions:', {
  width: cy.container().clientWidth,
  height: cy.container().clientHeight
});

// Check if nodes are visible
cy.nodes().forEach(node => {
  const pos = node.position();
  console.log(`Node ${node.id()}:`, {
    position: pos,
    visible: node.visible(),
    renderedPosition: node.renderedPosition()
  });
});
```

## What to Look For

### ✅ Good Output:
```
=== GRAPH DIAGNOSTICS ===
Cytoscape exists: true
Total nodes: 5
Total edges: 4
Node IDs: ["10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4", "10.1.1.5"]
Edge IDs: ["10.1.1.1-10.1.1.2", "10.1.1.1-10.1.1.3", ...]
...
```

### ❌ Bad Output:
```
Total nodes: 1  ← Only initial node, expansion didn't work
Total edges: 0  ← No connections
```

## Force Graph to Show Nodes

If nodes exist but aren't visible, paste this:

```javascript
// Force show all nodes
console.log('Forcing graph update...');
cy.nodes().forEach(n => n.show());
cy.edges().forEach(e => e.show());
cy.fit(null, 50);
console.log('Done - you should see the graph now');
```

## Manually Add a Test Node

To verify Cytoscape is working:

```javascript
// Add a test node
cy.add({
  group: 'nodes',
  data: { id: 'test-node', label: 'TEST', color: '#ff0000', size: 60 }
});
cy.add({
  group: 'edges',
  data: { id: 'test-edge', source: cy.nodes()[0].id(), target: 'test-node' }
});
cy.layout({ name: 'cose', fit: true }).run();
console.log('Test node added - do you see a big red node?');
```

## Check What Happens on Expand

Before clicking "Discover Neighbors", paste this:

```javascript
// Monitor all Cytoscape events
cy.on('add', 'node', function(evt) {
  console.log('🟢 NODE ADDED:', evt.target.id());
});
cy.on('add', 'edge', function(evt) {
  console.log('🔗 EDGE ADDED:', evt.target.id());
});
cy.on('layoutstart', function() {
  console.log('📐 LAYOUT STARTED');
});
cy.on('layoutstop', function() {
  console.log('📐 LAYOUT STOPPED');
});
console.log('Event listeners installed - now click "Discover Neighbors"');
```

Then click the button and watch for these events in the console.

## Expected Flow

When you click "Discover Neighbors", you should see:

```
API Response: {success: true, ...}
Expanding node: 10.1.1.1 with 3 neighbors
[0] Adding neighbor: 10.1.1.2
🟢 NODE ADDED: 10.1.1.2
✓ Added neighbor node: 10.1.1.2 1 elements
🔗 EDGE ADDED: 10.1.1.1-10.1.1.2
✓ Added edge: 10.1.1.1-10.1.1.2 1 elements
[1] Adding neighbor: 10.1.1.3
🟢 NODE ADDED: 10.1.1.3
...
Summary: Added 3 nodes and 3 edges
Current graph state: 4 nodes, 3 edges
Running layout...
📐 LAYOUT STARTED
📐 LAYOUT STOPPED
Layout complete - fitting to viewport
```

## If Still Not Working

Run this to export graph data:

```javascript
// Export graph state
const graphData = {
  nodes: cy.nodes().map(n => ({
    id: n.id(),
    data: n.data(),
    position: n.position()
  })),
  edges: cy.edges().map(e => ({
    id: e.id(),
    source: e.data('source'),
    target: e.data('target')
  }))
};
console.log('Graph export:', JSON.stringify(graphData, null, 2));
```

Copy this output and share it - it will show exactly what's in the graph.

## Nuclear Option - Force Re-render

```javascript
// Destroy and recreate layout
console.log('Forcing complete re-render...');
cy.layout({
  name: 'preset',
  fit: true
}).run();
setTimeout(() => {
  cy.layout({
    name: 'cose',
    animate: true,
    fit: true,
    padding: 50
  }).run();
}, 100);
```

## Check If It's a Viewport Issue

```javascript
// Check if nodes exist but are off-screen
const allNodes = cy.nodes();
console.log('All nodes:', allNodes.map(n => ({
  id: n.id(),
  position: n.position(),
  boundingBox: n.boundingBox()
})));

// Force zoom way out
cy.zoom(0.1);
cy.center();
console.log('Zoomed out to 10% - can you see any dots?');
```

---

## Share This Info

If still having issues, share:
1. Output from the diagnostic script (first one)
2. Browser console screenshot after clicking expand
3. Output from graph export
4. Whether test node appears (red node test)

This will help identify if it's a Cytoscape issue, data issue, or viewport issue.
