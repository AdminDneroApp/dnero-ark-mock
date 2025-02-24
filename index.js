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
  
    const statusArray = statuses ? statuses.split(',').map(Number) : [];
    const pageSizeInt = pageSize ? parseInt(pageSize, 10) : null;
    const pageInt = page ? parseInt(page, 10) : null;
    const reverse = reverseOrder === 'true';
  
    // Query to only retrieve transactions where the session user matches the primary 'user' field
    let query = `
      SELECT * FROM transactions 
      WHERE user->>'userId' = ?
    `;
    let queryParams = [req.user];
  
    if (statusArray.length > 0) {
      query += ' AND coinStatus IN (' + statusArray.map(() => '?').join(', ') + ')';
      queryParams.push(...statusArray);
    }
  
    let limitOffsetClause = '';
    if (pageSizeInt && pageInt) {
      const offset = (pageInt - 1) * pageSizeInt;
      limitOffsetClause = ` LIMIT ? OFFSET ?`;
      queryParams.push(pageSizeInt, offset);
    }
  
    db.all(query + limitOffsetClause, queryParams, async (err, rows) => {
      if (err) {
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred while retrieving the transactions.",
        });
      }
  
      if (rows.length === 0) {
        return res.status(404).json({
          event: "TRANSACTIONS_NOT_FOUND",
          message: "No transactions were found.",
        });
      }
  
      rows = rows.map((row) => {
        row.user = JSON.parse(row.user);
        row.relatedUser = JSON.parse(row.relatedUser);
  
        // Determine 'from' and 'to' based on the interactionType
        if (row.interactionType === 0) {
          // Sender interaction
          row.from = row.user;
          row.to = row.relatedUser;
        } else if (row.interactionType === 1) {
          // Receiver interaction
          row.from = row.relatedUser;
          row.to = row.user;
        }
  
        // Remove unnecessary raw user fields
        delete row.user;
        delete row.relatedUser;
  
        return row;
      });
  
      if (reverse) {
        rows.reverse();
      }
  
      res.status(200).json({ transactions: rows });
    });
  });
  
  

  //----------------------- Coins ----------------------------//

  //returns the coins for a given user weather the user is the sender or recipeient of the coins
  app.get('/DneroArk/coins', checkAccessToken, (req, res) => {
    const { statuses, pageSize, page, sortOrder, verbose } = req.query;
  
    // Validate and parse parameters
    const statusArray = statuses
      ? statuses.split(',').map(s => parseInt(s, 10)).filter(Number.isInteger)
      : [];
    const pageSizeInt = pageSize ? parseInt(pageSize, 10) : 10;
    const pageInt = page ? parseInt(page, 10) : 1;
    const sort = sortOrder ?? 'ASC'; // Default to ascending
    const additionalInfo = verbose === 'true';

    // Validate pagination
    if (pageInt <= 0 || pageSizeInt <= 0) {
      return res.status(422).json({
        event: "UNPROCESSABLE_ENTITY",
        message: "Pagination values must be greater than zero."
      });
    }
  
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
  
    // Prepare base query and parameters
    let baseQuery = `FROM coins WHERE (userRecipient->>'userId' = ? OR userSender->>'userId' = ?)`;
    let queryParams = [req.user, req.user];
  
    // Apply status filtering only if statuses are provided
    if (statusArray.length > 0) {
      baseQuery += ` AND coinStatus IN (${statusArray.map(() => '?').join(', ')})`;
      queryParams.push(...statusArray);
    }
  
    // Get total count of matching records
    const countQuery = `SELECT COUNT(*) AS total ${baseQuery}`;
  
    db.get(countQuery, queryParams, (err, countResult) => {
      if (err) {
        console.error("Error counting coins:", err);
        return res.status(500).json({
          event: "INTERNAL_SERVER_ERROR",
          message: "An error occurred while counting records."
        });
      }
  
      const totalElements = countResult?.total || 0;
  
      // If no records found, return 404
      if (totalElements === 0) {
        return res.status(404).json({
          event: "RESOURCE_NOT_FOUND",
          message: "No coins were found for the provided filters."
        });
      }
  
      // Fetch paginated results
      let dataQuery = `SELECT * ${baseQuery} ORDER BY redeemedDate ${sort}`;
      if (pageSizeInt && pageInt) {
        const offset = (pageInt - 1) * pageSizeInt;
        dataQuery += ` LIMIT ? OFFSET ?`;
        queryParams.push(pageSizeInt, offset);
      }
  
      db.all(dataQuery, queryParams, async (err, rows) => {
        if (err) {
          console.error("Error querying coins:", err);
          return res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "An error occurred while fetching records."
          });
        }
  
        try {
          // Process user details if verbose mode is enabled
          rows = await Promise.all(
            rows.map(async (row) => {
              if (row.userRecipient) row.userRecipient = JSON.parse(row.userRecipient);
              if (row.userSender) row.userSender = JSON.parse(row.userSender);
  
              if (additionalInfo) {
                const fetchUserDetails = async (userId) => {
                  return new Promise((resolve, reject) => {
                    db.get(
                      `SELECT firstName, lastName, imgUrl FROM users WHERE userId = ?`,
                      [userId],
                      (err, user) => (err ? reject(err) : resolve(user))
                    );
                  });
                };
  
                if (row.userRecipient?.userId) {
                  const recipient = await fetchUserDetails(row.userRecipient.userId);
                  if (recipient) {
                    row.userRecipient = { ...row.userRecipient, ...recipient };
                  }
                }
  
                if (row.userSender?.userId) {
                  const sender = await fetchUserDetails(row.userSender.userId);
                  if (sender) {
                    row.userSender = { ...row.userSender, ...sender };
                  }
                }
              }
  
              return row;
            })
          );
  
          // Prepare response with pagination details
          const totalPages = Math.ceil(totalElements / pageSizeInt);
          const hasMore = pageInt < totalPages;
  
          res.status(200).json({
            coins: rows,
            pagination: {
              page: pageInt,
              pageSize: pageSizeInt,
              totalElements,
              totalPages,
              hasMore
            }
          });
        } catch (error) {
          console.error("Error processing coins:", error);
          res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "An error occurred while processing the request."
          });
        }
      });
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

  //
  app.post("/DneroArk/coins/redeem/:coinId", checkAccessToken, async (req, res) => {
    const coinId = parseInt(req.params.coinId, 10);
  
    if (isNaN(coinId)) {
      return res.status(400).json({
        event: "INVALID_PARAMETERS",
        message: "One or more query parameters are invalid or malformed.",
      });
    }
  
    const query = `SELECT * FROM coins WHERE coinId = ?`;
  
    db.get(query, [coinId], (err, coin) => {
      if (err) {
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
  
      db.run(updateQuery, [redeemedDate, 2, coinId], async function (err) {
        if (err) {
          return res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "An unexpected error occurred. Please try again later.",
          });
        }
  
        const updatedCoin = { ...coin, redeemedDate, coinStatus: 2 };
  
        let senderId = "";
        let receiverId = "";
  
        try {
          if (updatedCoin.userRecipient) {
            updatedCoin.userRecipient = JSON.parse(updatedCoin.userRecipient);
            receiverId = updatedCoin.userRecipient.userId;
          }
          if (updatedCoin.userSender) {
            updatedCoin.userSender = JSON.parse(updatedCoin.userSender);
            senderId = updatedCoin.userSender.userId;
          }
        } catch (err) {
          return res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "Failed to parse user details. Please try again later.",
          });
        }
  
        // Check sender's balance before processing redemption
        try {
          const senderWallet = await new Promise((resolve, reject) => {
            const walletQuery = `SELECT cashBalance FROM wallet WHERE userId = ?`;
            db.get(walletQuery, [senderId], (err, row) => {
              if (err) reject(err);
              else resolve(row);
            });
          });
  
          console.log("Sender wallet:", senderWallet);
  
          if (!senderWallet || senderWallet.cashBalance === undefined) {
            console.error(
              "Sender wallet not found or cashBalance is undefined:",
              senderId
            );
            return res.status(400).json({
              event: "INSUFFICIENT_FUNDS",
              message: "Coin cannot be collected right now.",
            });
          }
  
          const senderBalance = parseFloat(senderWallet.cashBalance);
          const coinAmount = parseFloat(coin.cashAmount);
  
          if (senderBalance < coinAmount) {
            console.error("[CHECK] Insufficient funds! Transaction blocked.");
            return res.status(400).json({
              event: "INSUFFICIENT_FUNDS",
              message: "Coin cannot be collected right now.",
            });
          }
        } catch (err) {
          console.error("Error checking sender's balance:", err);
          return res.status(500).json({
            event: "INTERNAL_SERVER_ERROR",
            message: "Failed to verify sender's balance. Please try again later.",
          });
        }
  
        const walletUpdateQuery = `
          UPDATE wallet
          SET cashBalance = CASE
            WHEN userId = ? THEN cashBalance - ?
            WHEN userId = ? THEN cashBalance + ?
          END
          WHERE userId IN (?, ?)
        `;
  
        db.run(
          walletUpdateQuery,
          [senderId, coin.cashAmount, receiverId, coin.cashAmount, senderId, receiverId],
          function (err) {
            if (err) {
              return res.status(500).json({
                event: "INTERNAL_SERVER_ERROR",
                message: "An unexpected error occurred. Please try again later.",
              });
            }
  
            const userDetailsQuery = `SELECT userId, firstName, lastName FROM users WHERE userId IN (?, ?)`;
  
            db.all(userDetailsQuery, [senderId, receiverId], (err, users) => {
              if (err) {
                return res.status(500).json({
                  event: "INTERNAL_SERVER_ERROR",
                  message: "An unexpected error occurred while fetching user details.",
                });
              }
  
              let senderDetails = {};
              let recipientDetails = {};
  
              users.forEach((user) => {
                if (user.userId === senderId) {
                  senderDetails = {
                    userId: senderId,
                    firstName: user.firstName,
                    lastName: user.lastName,
                  };
                }
                if (user.userId === receiverId) {
                  recipientDetails = {
                    userId: receiverId,
                    firstName: user.firstName,
                    lastName: user.lastName,
                  };
                }
              });
  
              const transactionInsert = (transactionId, interactionType, userDetails, relatedUserDetails) => {
                return new Promise((resolve, reject) => {
                  const query = `
                    INSERT INTO transactions (transactionId, interactionType, amount, coinStatus, expirationDate, capturedDate, createDate, user, relatedUser)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                  `;
  
                  db.run(
                    query,
                    [
                      transactionId,
                      interactionType,
                      coin.cashAmount,
                      2, // Coin status for redeemed
                      coin.expirationDate,
                      redeemedDate,
                      new Date().toISOString(),
                      JSON.stringify(userDetails),
                      JSON.stringify(relatedUserDetails),
                    ],
                    function (err) {
                      if (err) reject(err);
                      else resolve();
                    }
                  );
                });
              };
  
              // Generate transaction IDs using UUIDs
              const senderTransactionId = Math.floor(Math.random() * 900) + 100;
              const recipientTransactionId = Math.floor(Math.random() * 900) + 100;              
  
              Promise.allSettled([
                transactionInsert(senderTransactionId, 0, senderDetails, recipientDetails),
                transactionInsert(recipientTransactionId, 1, recipientDetails, senderDetails),
              ]).then((results) => {
                results.forEach((result, index) => {
                  if (result.status === "rejected") {
                    console.error(`Transaction ${index} failed:`, result.reason);
                  }
                });
  
                if (results.some((r) => r.status === "rejected")) {
                  return res.status(500).json({
                    event: "INTERNAL_SERVER_ERROR",
                    message: "Failed to record transactions. Please try again later.",
                  });
                }
  
                if (updatedCoin.userSender) {
                  updatedCoin.userSender.firstName = senderDetails.firstName;
                  updatedCoin.userSender.lastName = senderDetails.lastName;
                }
  
                if (updatedCoin.userRecipient) {
                  updatedCoin.userRecipient.firstName = recipientDetails.firstName;
                  updatedCoin.userRecipient.lastName = recipientDetails.lastName;
                }
  
                return res.status(200).json(updatedCoin);
              });
            });
          }
        );
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

      // Get sender's current balance and pending coins
      const senderWallet = await new Promise((resolve, reject) => {
        const walletQuery = `SELECT cashBalance FROM wallet WHERE userId = ?`;
        db.get(walletQuery, [req.user], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });


      if (senderWallet < parseFloat(cashAmount)) {
        return res.status(400).json({
          event: "INSUFFICIENT_BALANCE",
          message: "Your balance is not sufficient to drop this coin.",
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

      if (createdCoins.length > 0) {
        return res.status(201).json({
          event: "THROW_SUCCESS",
          message: "Coin successfully thrown.",
          data: createdCoins,
        });
      } else {
        return res.status(400).json({
          event: "INVALID_PARAMETERS",
          message: "No valid users found",
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
