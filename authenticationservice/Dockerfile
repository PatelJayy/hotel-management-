# Use an official Node.js runtime as a base image
FROM node:18.17.0-alpine3.17

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install application dependencies
RUN npm install

# Copy the application code to the working directory
COPY app.js .
COPY auth.js .
COPY authRouter.js .
COPY database.db .

# Expose a port for the application to listen on (adjust as needed)
EXPOSE 3003

# Command to run the application
CMD ["node", "app.js"]
