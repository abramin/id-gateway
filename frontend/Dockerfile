# Frontend Dockerfile for ID Gateway UI
# Uses nginx to serve static files

FROM nginx:alpine

# Copy static files to nginx html directory
COPY public /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
