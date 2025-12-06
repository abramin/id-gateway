// Attack Paths Demo Component
// Implements animated attack visualizations for OAuth 2.0

document.addEventListener('alpine:init', () => {
  Alpine.data('attackPathsDemo', () => ({
    // State
    attacks: ATTACK_SCENARIOS,
    selectedAttack: null,
    currentStep: 0,
    animating: false,

    init() {
      // Position diagram nodes on load
      this.positionNodes();
      window.addEventListener('resize', () => this.positionNodes());
    },

    // Position diagram nodes in default layout
    positionNodes() {
      const container = document.getElementById('attack-diagram');
      if (!container) return;

      const width = container.offsetWidth;
      const height = container.offsetHeight || 400;

      // Default positions (4-node diamond layout)
      const positions = {
        user: { x: width * 0.15, y: height * 0.5 },
        client: { x: width * 0.85, y: height * 0.5 },
        authServer: { x: width * 0.5, y: height * 0.2 },
        resourceServer: { x: width * 0.5, y: height * 0.8 },
        attacker: { x: width * 0.5, y: height * 0.5 } // Center, hidden by default
      };

      Object.keys(positions).forEach(nodeId => {
        const node = document.getElementById(`node-${nodeId}`);
        if (node) {
          node.style.left = `${positions[nodeId].x}px`;
          node.style.top = `${positions[nodeId].y}px`;
        }
      });
    },

    // Select an attack scenario
    selectAttack(attack) {
      this.selectedAttack = attack;
      this.currentStep = 0;
      this.resetDiagram();
      this.$nextTick(() => {
        this.renderStep();
      });
    },

    // Reset diagram to initial state
    resetDiagram() {
      // Reset all nodes
      ['user', 'client', 'authServer', 'resourceServer', 'attacker'].forEach(nodeId => {
        const node = document.getElementById(`node-${nodeId}`);
        if (node) {
          node.classList.remove('active', 'attack', 'compromised', 'faded', 'hidden');
          const status = node.querySelector('.node-status');
          if (status) status.textContent = '';
        }
      });

      // Hide attacker by default
      const attackerNode = document.getElementById('node-attacker');
      if (attackerNode) attackerNode.classList.add('hidden');

      // Clear all arrows
      this.clearArrows();

      // Reposition nodes
      this.positionNodes();
    },

    // Clear all arrows from SVG canvas
    clearArrows() {
      const canvas = document.getElementById('arrow-canvas');
      if (canvas) {
        // Remove all path elements (arrows)
        const paths = canvas.querySelectorAll('path:not([id^="arrow-"])');
        paths.forEach(path => path.remove());

        // Remove all text elements (labels)
        const texts = canvas.querySelectorAll('text');
        texts.forEach(text => text.remove());

        // Remove all rect elements (label backgrounds)
        const rects = canvas.querySelectorAll('rect');
        rects.forEach(rect => rect.remove());
      }
    },

    // Go to next step
    nextStep() {
      if (!this.selectedAttack || this.currentStep >= this.selectedAttack.steps.length - 1) return;
      this.currentStep++;
      this.renderStep();
    },

    // Go to previous step
    previousStep() {
      if (this.currentStep <= 0) return;
      this.currentStep--;
      this.renderStep();
    },

    // Reset animation to beginning
    resetAnimation() {
      this.currentStep = 0;
      this.resetDiagram();
      this.$nextTick(() => {
        this.renderStep();
      });
    },

    // Render current step
    renderStep() {
      if (!this.selectedAttack || this.animating) return;

      this.animating = true;
      this.resetDiagram();

      const diagramAction = this.selectedAttack.diagramActions[this.currentStep];
      if (!diagramAction) {
        this.animating = false;
        return;
      }

      // Apply node visibility and styling
      if (diagramAction.nodes) {
        this.applyNodeStyling(diagramAction);
      }

      // Apply arrows
      if (diagramAction.arrows) {
        this.$nextTick(() => {
          this.drawArrows(diagramAction.arrows);
        });
      }

      // Apply labels
      if (diagramAction.labels) {
        this.applyLabels(diagramAction.labels);
      }

      // Apply attacker positioning
      if (diagramAction.attackerPosition) {
        this.positionAttacker(diagramAction.attackerPosition, diagramAction);
      }

      // Animate step transition
      this.animateStepTransition(diagramAction);

      setTimeout(() => {
        this.animating = false;
      }, 600);
    },

    // Apply node styling based on action
    applyNodeStyling(action) {
      const allNodes = ['user', 'client', 'authServer', 'resourceServer', 'attacker'];

      allNodes.forEach(nodeId => {
        const node = document.getElementById(`node-${nodeId}`);
        if (!node) return;

        if (action.nodes.includes(nodeId)) {
          // Node is active in this step
          node.classList.remove('hidden', 'faded');
          node.classList.add('active');

          // Apply action-specific styling
          if (action.action === 'highlightAttack' || action.action === 'showAttack') {
            if (nodeId === 'attacker') {
              node.classList.add('attack');
            }
          }

          if (action.action === 'showCompromised') {
            if (nodeId === 'resourceServer' || nodeId === 'client') {
              node.classList.add('compromised');
            }
            if (nodeId === 'attacker') {
              node.classList.add('attack');
            }
          }
        } else {
          // Node is not active - fade it
          if (nodeId === 'attacker') {
            node.classList.add('hidden');
          } else {
            node.classList.add('faded');
          }
        }
      });
    },

    // Draw arrows between nodes
    drawArrows(arrows) {
      const canvas = document.getElementById('arrow-canvas');
      if (!canvas) return;

      arrows.forEach((arrow, index) => {
        const fromNode = document.getElementById(`node-${arrow.from}`);
        const toNode = document.getElementById(`node-${arrow.to}`);

        if (!fromNode || !toNode) return;

        const fromRect = fromNode.getBoundingClientRect();
        const toRect = toNode.getBoundingClientRect();
        const containerRect = canvas.getBoundingClientRect();

        // Calculate center points relative to container
        const fromX = fromRect.left + fromRect.width / 2 - containerRect.left;
        const fromY = fromRect.top + fromRect.height / 2 - containerRect.top;
        const toX = toRect.left + toRect.width / 2 - containerRect.left;
        const toY = toRect.top + toRect.height / 2 - containerRect.top;

        // Calculate arrow vector
        const dx = toX - fromX;
        const dy = toY - fromY;
        const distance = Math.sqrt(dx * dx + dy * dy);

        // Shorten arrow to not overlap with nodes (node radius ~40px)
        const nodeRadius = 40;
        const startX = fromX + (dx / distance) * nodeRadius;
        const startY = fromY + (dy / distance) * nodeRadius;
        const endX = toX - (dx / distance) * nodeRadius;
        const endY = toY - (dy / distance) * nodeRadius;

        // Determine arrow color and style
        const color = this.getArrowColor(arrow.color);
        const strokeDasharray = arrow.style === 'dashed' ? '5,5' : 'none';

        // Create path element
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');

        // Use curved path for visual appeal - offset curve more to avoid nodes
        const controlX = (startX + endX) / 2;
        const controlY = (startY + endY) / 2 - 40; // Increased offset for better clearance

        path.setAttribute('d', `M ${startX} ${startY} Q ${controlX} ${controlY} ${endX} ${endY}`);
        path.setAttribute('stroke', color);
        path.setAttribute('stroke-width', '3'); // Thicker for better visibility
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke-dasharray', strokeDasharray);
        path.setAttribute('marker-end', `url(#arrow-${arrow.color})`);
        path.classList.add('arrow');

        canvas.appendChild(path);

        // Add label if provided
        if (arrow.label) {
          // Add background rectangle first (so it appears behind text)
          const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          const textWidth = arrow.label.length * 8; // Slightly wider estimate
          const textHeight = 20; // Taller for better padding
          rect.setAttribute('x', controlX - textWidth / 2 - 4);
          rect.setAttribute('y', controlY - textHeight + 2);
          rect.setAttribute('width', textWidth + 8);
          rect.setAttribute('height', textHeight);
          rect.setAttribute('fill', 'white');
          rect.setAttribute('stroke', color);
          rect.setAttribute('stroke-width', '2');
          rect.setAttribute('opacity', '0.95');
          rect.setAttribute('rx', '4');
          rect.classList.add('arrow-label-bg');

          canvas.appendChild(rect);

          // Add text on top of background
          const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          text.setAttribute('x', controlX);
          text.setAttribute('y', controlY - 4);
          text.setAttribute('text-anchor', 'middle');
          text.setAttribute('dominant-baseline', 'middle');
          text.setAttribute('fill', color);
          text.setAttribute('font-size', '13');
          text.setAttribute('font-weight', 'bold');
          text.classList.add('arrow-label');
          text.textContent = arrow.label;

          canvas.appendChild(text);
        }

        // Animate arrow drawing
        const pathLength = path.getTotalLength();
        path.style.strokeDasharray = `${pathLength} ${pathLength}`;
        path.style.strokeDashoffset = pathLength;

        anime({
          targets: path,
          strokeDashoffset: [pathLength, 0],
          duration: 800,
          delay: index * 200,
          easing: 'easeInOutQuad'
        });
      });
    },

    // Get arrow color based on type
    getArrowColor(colorType) {
      const colors = {
        normal: '#3b82f6',
        attack: '#dc2626',
        compromised: '#7c3aed',
        faded: '#9ca3af'
      };
      return colors[colorType] || colors.normal;
    },

    // Apply text labels to nodes
    applyLabels(labels) {
      labels.forEach(label => {
        const node = document.getElementById(`node-${label.node}`);
        if (!node) return;

        const statusEl = node.querySelector('.node-status');
        if (statusEl) {
          statusEl.textContent = label.text;
        }
      });
    },

    // Position attacker node dynamically
    positionAttacker(position, action) {
      const attackerNode = document.getElementById('node-attacker');
      if (!attackerNode) return;

      const container = document.getElementById('attack-diagram');
      const width = container.offsetWidth;
      const height = container.offsetHeight || 400;

      let x, y;

      if (position === 'middle') {
        // Position between two nodes if arrows are defined
        if (action.arrows && action.arrows.length > 0) {
          const firstArrow = action.arrows[0];
          const fromNode = document.getElementById(`node-${firstArrow.from}`);
          const toNode = document.getElementById(`node-${firstArrow.to}`);

          if (fromNode && toNode) {
            const fromRect = fromNode.getBoundingClientRect();
            const toRect = toNode.getBoundingClientRect();
            const containerRect = container.getBoundingClientRect();

            const fromX = fromRect.left + fromRect.width / 2 - containerRect.left;
            const fromY = fromRect.top + fromRect.height / 2 - containerRect.top;
            const toX = toRect.left + toRect.width / 2 - containerRect.left;
            const toY = toRect.top + toRect.height / 2 - containerRect.top;

            x = (fromX + toX) / 2;
            y = (fromY + toY) / 2;
          }
        }
      } else if (position === 'top') {
        x = width * 0.5;
        y = height * 0.1;
      } else if (position === 'bottom') {
        x = width * 0.5;
        y = height * 0.9;
      }

      if (x && y) {
        attackerNode.style.left = `${x}px`;
        attackerNode.style.top = `${y}px`;
      }
    },

    // Animate step transition with anime.js
    animateStepTransition(action) {
      // Pulse effect on active nodes
      const activeNodes = (action.nodes || []).map(nodeId => `#node-${nodeId}`).join(',');

      if (activeNodes) {
        anime({
          targets: activeNodes,
          scale: [0.95, 1],
          duration: 400,
          easing: 'easeOutElastic(1, .8)'
        });
      }

      // Shake effect for attack nodes
      if (action.action === 'highlightAttack' || action.action === 'showAttack') {
        anime({
          targets: '#node-attacker',
          translateX: [
            { value: -5, duration: 50 },
            { value: 5, duration: 50 },
            { value: -5, duration: 50 },
            { value: 5, duration: 50 },
            { value: 0, duration: 50 }
          ],
          easing: 'linear'
        });
      }

      // Fade in effect for compromised state
      if (action.action === 'showCompromised') {
        const compromisedNodes = action.nodes
          .filter(n => n === 'resourceServer' || n === 'client')
          .map(n => `#node-${n}`)
          .join(',');

        if (compromisedNodes) {
          anime({
            targets: compromisedNodes,
            backgroundColor: ['#ffffff', '#f3e8ff', '#ffffff'],
            duration: 1000,
            easing: 'easeInOutQuad'
          });
        }
      }
    }
  }));
});
