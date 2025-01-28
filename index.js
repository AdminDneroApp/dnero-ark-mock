// Import the express module
import express from 'express'; 
import * as crypto from 'crypto';
import jwt from 'jsonwebtoken'; // Using ES module syntax for jsonwebtoken
import db from './setupDb.js';

const app = express();
const port = 3000; // The port where the app will listen
app.use(express.json());  
//---------------------------API CHANGES--------------------------------/


const checkAccessToken = (req, res, next) => {
  const authorization = req.headers.authorization;
  // Check if the Authorization header exists and starts with Bearer
  if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: Missing or invalid Bearer token' });
  }
  // Extract the token from the Authorization header
  const token = authorization.split(' ')[1];

  try{

    // Decode the token without verifying its signature
    const decoded = jwt.decode(token);
    const user = decryptHash( decoded.db_user_id)

    if (!user) {
      return res.status(400).json({ error: 'No user data in token' });
  }
  // Attach user data to the request object for further use
  req.user = user;
  next(); // Continue to the next middleware or route handler
  } catch (error) {
    console.log("error: "+ error)
      return res.status(400).json({ error: 'Invalid or expired token' });
  }
};

const decryptHash = (hash) => {
  // Decryption parameters
  const key = Buffer.from('f3b7a9c4d0e83f2eab7c94d63c76aeb27c391ad3e586c5f7294bc518607d91ef', 'hex');
  const iv = Buffer.from('a7f9c1e8b6d4f2e9ac8f6b4d9a3c8f1e', 'hex'); // Put the encrypted credential here

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decryptedCredential = decipher.update(hash, 'hex', 'utf8');
  decryptedCredential += decipher.final('utf8');

  return decryptedCredential;
};


//----------------------- User ----------------------------//

//This endpoint verifies whether the provided phone numbers exist in the system's records. 
// It ensures that only registered phone numbers are processed for further operations.
app.post('/DneroArk/user/contacts', checkAccessToken, (req, res) => {
  // Simulating an operation that returns users based on the phones and country codes in the body
  const requestBody = req.body;

  // Check if the request body is an array and contains objects with "phone" and "countryCode"
  if (!Array.isArray(requestBody) || !requestBody.every(item => item.phone && item.countryCode)) {
    return res.status(400).json({
      event: "MISSING_PARAMETERS",
      message: "The fields 'phone' and 'countryCode' are required but were not provided."
    });
  }

  // Return only the matching users 
  const requestedPhones = requestBody.map(item => ({
    phone: item.phone,
    countryCode: item.countryCode
  }));

  // Pull users from the database
  let query = `SELECT userId, firstName, lastName, imgUrl, deviceInfo
               FROM users WHERE`;

  let queryParams = [];

  requestedPhones.forEach((requested, index) => {
    const phoneCondition = `
      JSON_EXTRACT(deviceInfo, '$.phone') = ? AND (
        JSON_EXTRACT(deviceInfo, '$.countryCode') = ? OR 
        REPLACE(JSON_EXTRACT(deviceInfo, '$.countryCode'), '+', '') = ?
      )`;

    if (index > 0) {
      query += " OR ";  
    }
    query += phoneCondition;

    // Push values into the parameters array for the SQL query
    queryParams.push(requested.phone, requested.countryCode, requested.countryCode.replace('+', ''));
  });

  db.all(query, queryParams, (err, rows) => {
    if (err) {
      console.error("Error querying users:", err);
      return res.status(500).json({
        event: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred while processing the request. Please try again later."
      });
    }

    if (rows.length === 0) {
      return res.status(404).json({
        event: "PHONE_NOT_FOUND",
        message: "The phone number does not exist in our records."
      });
    }

    const formattedRows = rows.map(row => {
      try {
        // Parse the deviceInfo field into an object
        row.deviceInfo = JSON.parse(row.deviceInfo);
        // Return the formatted user object
        return {
          userId: row.userId,
          firstName: row.firstName,
          lastName: row.lastName,
          imgUrl: row.imgUrl,
          deviceInfo: row.deviceInfo
        };
      } catch (err) {
        console.error("Error parsing deviceInfo:", err);
        return row; // If error parsing, return the row as-is
      }
    });

    // Return the found users
    res.json(formattedRows);
  });
});


//Returns the balance of a user's crypto and cash balance from their wallet
app.get('/DneroArk/user/balance/:userId', checkAccessToken, (req, res) => {
  const userId = req.params.userId; // Correctly access the 'id' parameter
  console.log("userId: " + userId);

  // Check if userId is missing or invalid (400 Bad Request)
  if (!userId) {
    return res.status(400).json({
      event: "INVALID_REQUEST",
      message: "Invalid or missing id"
    });
  }

  // Query to get the cashBalance and cryptoBalance for the given userId
  const query = `
    SELECT cashBalance, cryptoBalance
    FROM wallet
    WHERE userId = ?
  `;

  // Execute the SQL query
  db.get(query, [userId], (err, row) => {
    if (err) {
      console.error("Error fetching balance:", err);
      return res.status(500).json({
        event: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred while processing the request. Please try again later."
      });
    }

    if (!row) {
      return res.status(404).json({
        event: "USER_NOT_FOUND",
        message: "The user with the provided ID does not exist."
      });
    }

    // Return the balance details
    return res.status(200).json({
      cashBalance: row.cashBalance,
      cryptoBalance: row.cryptoBalance
    });
  });
});


//----------------------- Transactions ----------------------------//

  //Retrieves a single transaction's details based on its unique identifier.
  app.get('/DneroArk/transaction/:transactionId', checkAccessToken, (req, res) => {
    // Parse the transactionId and check if it's a valid number
    const transactionId = parseInt(req.params.transactionId, 10);
    
    // If the transactionId is not a valid number (bad request)
    if (isNaN(transactionId)) {
      return res.status(400).json({
        event: "INVALID_TRANSACTION_ID",
        message: "The provided transaction ID is invalid or malformed."
      });
    }
  
    // Query to fetch the transaction details by transactionId
    const query = 'SELECT * FROM transactions WHERE transactionId = ?';
    
    // Execute the SQL query
    db.get(query, [transactionId], (err, row) => {
      if (err) {
        console.error("Error fetching transaction:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while validating the OTP. Please try again later."
        });
      }
    
      if (!row) {
        // If no transaction is found, return a 404
        return res.status(404).json({
          event: "TRANSACTION_NOT_FOUND",
          message: "No transaction was found for the provided ID."
        });
      }
  
      try {
        // Attempt to parse the `user` field from the transaction (if it's a stringified JSON object)
        row.user = JSON.parse(row.user);
        
        // If the transaction data is successfully retrieved and parsed, return it
        res.status(200).json(row);
      } catch (parseErr) {
        // If there's an error parsing the `user` field, return a 500 error
        console.error("Error parsing JSON fields:", parseErr);
        res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while validating the OTP. Please try again later."
        });
      }
    });
  });  
  

  //Receives a list of transactions, starting from the most recent to the oldest.
  // If no parameters are provided, it returns all notifications from the most recent to the oldest by default.
  app.get('/DneroArk/transactions', checkAccessToken, (req, res) => {
    const { statuses, pageSize, page, reverseOrder } = req.query;
  
    // Validate and parse parameters
    const statusArray = statuses ? statuses.split(',').map(Number) : [];
    const pageSizeInt = pageSize ? parseInt(pageSize, 10) : null;
    const pageInt = page ? parseInt(page, 10) : null;
    const reverse = reverseOrder === 'true';
  
    // Validate the statuses parameter
    if (statuses && statusArray.some(isNaN)) {
      return res.status(400).json({
        event: "INVALID_STATUSES",
        message: "The provided statuses are invalid or malformed."
      });
    }
  
    // Validate pagination parameters
    if ((pageSizeInt && !pageInt) || (!pageSizeInt && pageInt)) {
      return res.status(400).json({
        event: "MISSING_PAGINATION",
        message: "Both 'pageSize' and 'page' are required when using the paginator."
      });
    }
  
    if (pageInt && pageInt <= 0) {
      return res.status(422).json({
        event: "INVALID_PAGE",
        message: "The page number must be a positive integer starting from 1."
      });
    }
  
    if (pageSizeInt && pageSizeInt <= 0) {
      return res.status(422).json({
        event: "INVALID_PAGE_SIZE",
        message: "The page size must be a positive integer."
      });
    }
  
    // Construct the base SQL query for retrieving transactions
    let query = `SELECT * FROM transactions WHERE user->>'userId' = ?`;
    let queryParams = [req.user];
  
    // Filter by status if provided
    if (statusArray.length > 0) {
      query += ' AND coinStatus IN (' + statusArray.map(() => '?').join(', ') + ')';
      queryParams.push(...statusArray); // Add the statuses to the query parameters
    }
  
    // Apply pagination if provided
    let limitOffsetClause = '';
    if (pageSizeInt && pageInt) {
      const offset = (pageInt - 1) * pageSizeInt;
      limitOffsetClause = ` LIMIT ? OFFSET ?`;
      queryParams.push(pageSizeInt, offset);
    }
  
    // Execute the query to fetch transactions
    db.all(query + limitOffsetClause, queryParams, async (err, rows) => {
      if (err) {
        console.error("Error querying transactions:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while retrieving the transactions. Please try again later."
        });
      }
  
      // Handle empty rows
      if (rows.length === 0) {
        return res.status(404).json({
          event: "TRANSACTIONS_NOT_FOUND",
          message: "No transactions were found for the given criteria."
        });
      }
  
      try {
        // Process rows to include user details with imgUrl
        rows = await Promise.all(
          rows.map(async (row) => {
            if (row.user) {
              row.user = JSON.parse(row.user); // Parse the 'user' field if it is JSON
  
              // Fetch the imgUrl for the user from the users table
              const user = await new Promise((resolve, reject) => {
                const query = `SELECT firstName, lastName, imgUrl FROM users WHERE userId = ?`;
                db.get(query, [row.user.userId], (err, userDetails) => {
                  if (err) reject(err);
                  else resolve(userDetails);
                });
              });
  
              if (user) {
                row.user.firstName = user.firstName;
                row.user.lastName = user.lastName;
                row.user.imgUrl = user.imgUrl; // Add imgUrl from users table
              }
            }
  
            return row;
          })
        );
  
        // Reverse the order if specified
        if (reverse) {
          rows.reverse();
        }
  
        // Prepare the response
        const response = {
          transactions: rows,
        };
  
        // Add pagination details if applicable
        if (pageSizeInt && pageInt) {
          response.page = pageInt;
          response.pageSize = pageSizeInt;
          response.totalTransactions = rows.length; // Adjust to reflect the total count in DB if available
        }
  
        res.status(200).json(response);
      } catch (error) {
        console.error("Error processing transactions:", error);
        res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while processing the transactions. Please try again later."
        });
      }
    });
  });
  

  //----------------------- Coins ----------------------------//

  //returns the coins for a given user weather the user is the sender or recipeient of the coins
  app.get('/DneroArk/coins', checkAccessToken, (req, res) => {
    const { statuses, pageSize, page, sortOrder, verbose } = req.query;
  
    // Validate and parse parameters
    const statusArray = statuses ? statuses.split(',').map(Number) : [];
    const pageSizeInt = pageSize ? parseInt(pageSize, 10) : null;
    const pageInt = page ? parseInt(page, 10) : null;
    const sort = sortOrder ?? 'ASC'; // Default to ascending
    const additionalInfo = verbose === 'true';
  
    // Validate pagination and status filters
    if ((pageSizeInt && !pageInt) || (!pageSizeInt && pageInt) || (pageInt && pageInt <= 0) || (pageSizeInt && pageSizeInt <= 0)) {
      return res.status(422).json({
        event: "UNPROCESSABLE_ENTITY",
        message: "The provided pagination values (page or pageSize) are invalid."
      });
    }
  
    if (statuses && statusArray.some(isNaN)) {
      return res.status(400).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed."
      });
    }
  
    // Prepare the base query to fetch coins from the database
    let query = `SELECT * FROM coins WHERE userRecipient->>'userId' = ? OR userSender->>'userId' = ?`;
    let queryParams = [req.user, req.user];
  
    // Filter by status if provided
    if (statusArray.length > 0) {
      query += ' AND coinStatus IN (' + statusArray.map(() => '?').join(', ') + ')';
      queryParams.push(...statusArray);
    }
  
    // Sort and paginate
    query += ` ORDER BY redeemedDate ${sort}`;
    if (pageSizeInt && pageInt) {
      const offset = (pageInt - 1) * pageSizeInt;
      query += ` LIMIT ? OFFSET ?`;
      queryParams.push(pageSizeInt, offset);
    }
  
    // Execute query
    db.all(query, queryParams, async (err, rows) => {
      if (err) {
        console.error("Error querying coins:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while processing the request. Please try again later."
        });
      }
  
      if (rows.length === 0) {
        return res.status(404).json({
          event: "RESOURCE_NOT_FOUND",
          message: "No coins were found for the provided filters."
        });
      }
  
      try {
        // Parse JSON fields and fetch additional data if verbose
        rows = await Promise.all(
          rows.map(async (row) => {
            if (row.userRecipient) row.userRecipient = JSON.parse(row.userRecipient);
            if (row.userSender) row.userSender = JSON.parse(row.userSender);
  
            // Add firstName, lastName, and imgUrl for verbose response
            if (additionalInfo) {
              if (row.userRecipient && row.userRecipient.userId) {
                const recipient = await new Promise((resolve, reject) => {
                  const query = `SELECT firstName, lastName, imgUrl FROM users WHERE userId = ?`;
                  db.get(query, [row.userRecipient.userId], (err, user) => {
                    if (err) reject(err);
                    else resolve(user);
                  });
                });
                if (recipient) {
                  row.userRecipient.firstName = recipient.firstName;
                  row.userRecipient.lastName = recipient.lastName; // Use imgUrl from users
                }
              }
  
              if (row.userSender && row.userSender.userId) {
                const sender = await new Promise((resolve, reject) => {
                  const query = `SELECT firstName, lastName, imgUrl FROM users WHERE userId = ?`;
                  db.get(query, [row.userSender.userId], (err, user) => {
                    if (err) reject(err);
                    else resolve(user);
                  });
                });
                if (sender) {
                  row.userSender.firstName = sender.firstName;
                  row.userSender.lastName = sender.lastName;
                  row.userSender.userImgUrl = sender.imgUrl; // Use imgUrl from users
                }
              }
            }
  
            return row;
          })
        );
  
        // Prepare response
        const response = {
          coins: rows.map((coin) => {
            if (additionalInfo) {
              return coin; // Include all details
            } else {
              return {
                coinId: coin.coinId,
                coinStatus: coin.coinStatus,
                latitude: coin.latitude,
                longitude: coin.longitude,
                message: coin.message,
                cashAmount: coin.cashAmount,
                creationDate: coin.creationDate,
                expirationDate: coin.expirationDate,
                redeemedDate: coin.redeemedDate,
                userSender: {
                  userId: coin.userSender.userId,
                  userImgUrl: coin.userSender.userImgUrl,
                  firstName: coin.userSender.firstName,
                  lastName: coin.userSender.lastName,
                },
                userRecipient: {
                  userId: coin.userRecipient.userId,
                  userImgUrl: coin.userRecipient.userImgUrl,
                  firstName: coin.userRecipient.firstName,
                  lastName: coin.userRecipient.lastName,
                },
              };
            }
          }),
        };
  
        // Add pagination if applicable
        if (pageSizeInt && pageInt) {
          response.page = pageInt;
          response.pageSize = pageSizeInt;
          response.totalElements = rows.length; // Adjust if total count is available
        }
  
        res.status(200).json(response);
      } catch (error) {
        console.error("Error processing coins:", error);
        res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while processing the request. Please try again later."
        });
      }
    });
  });
   

  // gets all pending coins for a given user
  app.get('/DneroArk/coins/pending', checkAccessToken, (req, res) => {
    const { pageSize, page, sortOrder, verbose } = req.query;
  
    // Validate and parse parameters
    const pageSizeInt = pageSize ? parseInt(pageSize, 10) : null;
    const pageInt = page ? parseInt(page, 10) : null;
    const sort = sortOrder ?? 'ASC'; // Default to ascending
    const additionalInfo = verbose === 'true';
  
    // Check for invalid query parameters
    if ((pageSizeInt && !pageInt) || (!pageSizeInt && pageInt)) {
      return res.status(422).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed."
      });
    }
  
    if (pageSizeInt && pageSizeInt <= 0) {
      return res.status(422).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed."
      });
    }
  
    if (pageInt && pageInt <= 0) {
      return res.status(422).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed."
      });
    }
  
    // Prepare the base query to fetch pending coins (status 1)
    let query = `SELECT * FROM coins WHERE userRecipient->>'userId' = ? AND coinStatus = 1`; // Assuming 'userRecipient' is stored as a JSON column
    let queryParams = [req.user]; // User ID from the access token
  
    // Sort by redeemedDate (most recent to oldest)
    query += ` ORDER BY redeemedDate ${sort}`;
  
    // Apply pagination if pageSize and page are provided
    let limitOffsetClause = '';
    if (pageSizeInt && pageInt) {
      const offset = (pageInt - 1) * pageSizeInt;
      limitOffsetClause = ` LIMIT ? OFFSET ?`;
      queryParams.push(pageSizeInt, offset);
    }
  
    // Execute the SQL query
    db.all(query + limitOffsetClause, queryParams, (err, rows) => {
      if (err) {
        console.error("Error querying coins:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred. Please try again later."
        });
      }
  
      // Handle no rows returned (no pending coins found)
      if (rows.length === 0) {
        return res.status(404).json({
          event: "RESOURCE_NOT_FOUND",
          message: "The requested resource could not be found."
        });
      }
  
      // Optionally, parse JSON fields if necessary (e.g., userRecipient, userSender, etc.)
      try {
        rows = rows.map(row => {
          if (row.userRecipient) {
            row.userRecipient = JSON.parse(row.userRecipient); 
          }
          if (row.userSender) {
            row.userSender = JSON.parse(row.userSender);
          }
          return row;
        });
  
        // Prepare the response, mapping coins
        let response = {
          coins: rows.map(coin => {
            if (additionalInfo) {
              // If verbose is true, return the entire coin object
              return coin;
            } else {
              // If verbose is false, return only selected fields
              return {
                coinId: coin.coinId,
                coinStatus: coin.coinStatus,
                latitude: coin.latitude,
                longitude: coin.longitude,
              };
            }
          }),
        };
  
        // Add pagination details to the response if pagination parameters were provided
        if (pageSizeInt && pageInt) {
          response.page = pageInt;
          response.pageSize = pageSizeInt;
          response.totalElements = rows.length; // You may want to adjust this to the actual total count
        }
  
        res.status(200).json(response);
      } catch (parseErr) {
        console.error("Error processing coin data:", parseErr);
        res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred. Please try again later."
        });
      }
    });
  });
  
  

// gets the coin count for all pending coins a user has sent or recieved 
app.get('/DneroArk/coins/pending/count', checkAccessToken, (req, res) => {
  // Ensure query parameters are valid (you can expand this validation if needed)
  const { pageSize, page } = req.query;

  // Validate that query parameters are valid
  if ((pageSize && !page) || (!pageSize && page)) {
    return res.status(422).json({
      event: "INVALID_PARAMETERS",
      message: "One or more query parameters are invalid or malformed."
    });
  }

  // Prepare the query to get the count of pending coins for the specified user
  const query = `
    SELECT COUNT(*) AS count 
    FROM coins 
    WHERE userRecipient->>'userId' = ? AND coinStatus = 1
  `;

  // Execute the SQL query
  db.get(query, [req.user], (err, row) => {
    if (err) {
      console.error("Error querying coins count:", err);
      return res.status(500).json({
        event: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred. Please try again later."
      });
    }

    // If no result found, return a 404 (optional, depending on the business logic)
    if (!row) {
      return res.status(404).json({
        event: "RESOURCE_NOT_FOUND",
        message: "The requested resource could not be found."
      });
    }

    // If no pending coins, return the count as 0
    const response = {
      count: row.count || 0
    };

    res.status(200).json(response);
  });
});



   //Retrieves a single coin and its details based on its unique identifier.
   app.get('/DneroArk/coins/:coinId', checkAccessToken, (req, res) => {
    const coinId = parseInt(req.params.coinId, 10);
  
    // Check if the coinId is a valid integer
    if (isNaN(coinId)) {
      return res.status(400).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed."
      });
    }
  
    // Query to get the coin by coinId
    const query = `
      SELECT * FROM coins WHERE coinId = ?
    `;
  
    // Execute the SQL query
    db.get(query, [coinId], (err, coin) => {
      if (err) {
        console.error("Error querying coin:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while processing the request. Please try again later."
        });
      }
  
      if (!coin) {
        return res.status(404).json({
          event: "RESOURCE_NOT_FOUND",
          message: "No coins were found for the provided filters."
        });
      }
  
      // Unstringify userSender and userRecipient
      try {
        if (coin.userSender) {
          coin.userSender = JSON.parse(coin.userSender);
        }
        if (coin.userRecipient) {
          coin.userRecipient = JSON.parse(coin.userRecipient);
        }
      } catch (parseError) {
        console.error("Error parsing user data:", parseError);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while processing the request. Please try again later."
        });
      }
  
      // Return the coin details with unstringified userSender and userRecipient
      res.status(200).json(coin);
    });
  });
  
  
  // sets the redeem date and status on the given coin
  app.post('/DneroArk/coins/redeem/:coinId', checkAccessToken, (req, res) => {
    const coinId = parseInt(req.params.coinId, 10);
  
    // Validate coinId
    if (isNaN(coinId)) {
      return res.status(400).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed.",
      });
    }
  
    const query = `SELECT * FROM coins WHERE coinId = ?`;
  
    db.get(query, [coinId], (err, coin) => {
      if (err) {
        console.error("Error querying coin:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred. Please try again later.",
        });
      }
  
      if (!coin) {
        return res.status(404).json({
          event: "COIN_NOT_FOUND",
          message: "The specified coin does not exist.",
        });
      }
  
      if (coin.coinStatus === 2) {
        return res.status(400).json({
          event: "COIN_ALREADY_REDEEMED",
          message: "The coin has already been redeemed.",
        });
      }
  
      const redeemedDate = new Date().toISOString();
      const updateQuery = `
        UPDATE coins
        SET redeemedDate = ?, coinStatus = ?
        WHERE coinId = ?
      `;
  
      db.run(updateQuery, [redeemedDate, 2, coinId], function (err) {
        if (err) {
          console.error("Error updating coin:", err);
          return res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "An unexpected error occurred. Please try again later.",
          });
        }
  
        const updatedCoin = { ...coin, redeemedDate, coinStatus: 2 };
  
        let senderId = '';
        let receiverId = '';
  
        if (updatedCoin.userRecipient) {
          updatedCoin.userRecipient = JSON.parse(updatedCoin.userRecipient);
          receiverId = updatedCoin.userRecipient.userId;
        }
        if (updatedCoin.userSender) {
          updatedCoin.userSender = JSON.parse(updatedCoin.userSender);
          senderId = updatedCoin.userSender.userId;
        }
  
        const walletUpdateQuery = `
          UPDATE wallet
          SET cashBalance = CASE
            WHEN userId = ? THEN cashBalance - ?
            WHEN userId = ? THEN cashBalance + ?
          END
          WHERE userId IN (?, ?)
        `;
  
        db.run(walletUpdateQuery, [senderId, coin.cashAmount, receiverId, coin.cashAmount, senderId, receiverId], function (err) {
          if (err) {
            console.error("Error updating wallet:", err);
            return res.status(500).json({
              event: "INTERNAL_SERVER_ERROR",
              message: "An unexpected error occurred. Please try again later.",
            });
          }
  
          // Fetch sender and recipient names
          const userDetailsQuery = `SELECT userId, firstName, lastName FROM users WHERE userId IN (?, ?)`;
  
          db.all(userDetailsQuery, [senderId, receiverId], (err, users) => {
            if (err) {
              console.error("Error fetching user details:", err);
              return res.status(500).json({
                event: "INTERNAL_SERVER_ERROR",
                message: "An unexpected error occurred. Please try again later.",
              });
            }
  
            users.forEach((user) => {
              if (user.userId === senderId) {
                updatedCoin.userSender.firstName = user.firstName;
                updatedCoin.userSender.lastName = user.lastName;
              }
              if (user.userId === receiverId) {
                updatedCoin.userRecipient.firstName = user.firstName;
                updatedCoin.userRecipient.lastName = user.lastName;
              }
            });
  
            return res.status(200).json(updatedCoin);
          });
        });
      });
    });
  });
  

   // drops a new coin for a given user based on their userId or phone number
   app.post('/DneroArk/coins/Drop', checkAccessToken, async (req, res) => {
    const { latitude, longitude, message, cashAmount, expirationDate, userRecipientId, userRecipientPhone } = req.body;
  
    if (!latitude || !longitude || !cashAmount || !expirationDate) {
      return res.status(400).json({
        event: "INVALID_PARAMETERS",
        message: "One or more required parameters are missing or invalid.",
      });
    }
  
    try {
      const sender = await new Promise((resolve, reject) => {
        const senderQuery = `SELECT * FROM users WHERE userId = ?`;
        db.get(senderQuery, [req.user], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
  
      if (!sender) {
        return res.status(404).json({
          event: "USER_NOT_AUTHORIZED",
          message: "You do not have permission to drop this coin.",
        });
      }
  
      const recipientIds = new Set();
  
      if (Array.isArray(userRecipientId)) {
        userRecipientId.forEach((id) => recipientIds.add(id));
      }
  
      if (Array.isArray(userRecipientPhone)) {
        for (const phone of userRecipientPhone) {
          const user = await new Promise((resolve, reject) => {
            const userQuery = `SELECT userId FROM users WHERE deviceInfo LIKE ?`;
            db.get(userQuery, [`%${phone}%`], (err, row) => {
              if (err) reject(err);
              else if (row) resolve(row.userId);
              else resolve(null);
            });
          });
  
          if (user) recipientIds.add(user);
        }
      }
  
      const createdCoins = [];
      for (const userId of recipientIds) {
        const user = await new Promise((resolve, reject) => {
          const userQuery = `SELECT userId, firstName, lastName, imgUrl FROM users WHERE userId = ?`;
          db.get(userQuery, [userId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
          });
        });
  
        if (user) {
          const existingCoin = await new Promise((resolve, reject) => {
            const checkCoinQuery = `SELECT * FROM coins WHERE latitude = ? AND longitude = ? AND userRecipient LIKE ?`;
            db.get(checkCoinQuery, [latitude, longitude, `%${userId}%`], (err, row) => {
              if (err) reject(err);
              else resolve(row);
            });
          });
  
          if (!existingCoin) {
            const coin = await new Promise((resolve, reject) => {
              const insertQuery = `
                INSERT INTO coins (coinId, coinStatus, latitude, longitude, message, cashAmount, creationDate, expirationDate, redeemedDate, userSender, userRecipient)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `;
              const coinId = Math.floor(Math.random() * 900) + 100;
              const creationDate = new Date().toISOString();
              db.run(
                insertQuery,
                [
                  coinId,
                  1,
                  latitude,
                  longitude,
                  message,
                  cashAmount,
                  creationDate,
                  expirationDate,
                  null,
                  JSON.stringify({ userId: req.user, userImgUrl: sender.imgUrl }),
                  JSON.stringify({ userId: user.userId, userImgUrl: user.imgUrl, firstName: user.firstName, lastName: user.lastName }),
                ],
                function (err) {
                  if (err) reject(err);
                  resolve({
                    coinId,
                    coinStatus: 1,
                    latitude,
                    longitude,
                    message,
                    cashAmount,
                    creationDate,
                    expirationDate,
                    redeemedDate: null,
                    userSender: { userId: req.user, userImgUrl: sender.imgUrl },
                    userRecipient: { userId: user.userId, userImgUrl: user.imgUrl, firstName: user.firstName, lastName: user.lastName },
                  });
                }
              );
            });
            createdCoins.push(coin);
          }
        }
      }
  
      if (createdCoins.length > 0) {
        return res.status(201).json({
          event: "THROW_SUCCESS",
          message: "Coin successfully thrown.",
          data: createdCoins,
        });
      } else {
        return res.status(400).json({
          event: "INVALID_PARAMETERS",
          message: "No valid users found or coins already exist at this location.",
        });
      }
    } catch (err) {
      console.error("Error:", err);
      return res.status(500).json({
        event: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred. Please try again later.",
      });
    }
  });
  
  


//-----------------------------------User Balance -------------------------/


// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
