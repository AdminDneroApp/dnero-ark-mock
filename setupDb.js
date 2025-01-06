import {transactions} from './mock-transactions.js';
import {coinsDb} from './mock-coins.js';
import {users} from './mock-users.js';
import sqlite3 from 'sqlite3'; 

const db = new sqlite3.Database('./arkMockDb.db');

const createTablesSQL = ` CREATE TABLE IF NOT EXISTS coins (
      coinId INTEGER PRIMARY KEY AUTOINCREMENT,
      coinStatus INTEGER,
      latitude TEXT,
      longitude TEXT,
      message TEXT,
      cashAmount TEXT,
      creationDate DATETIME,
      expirationDate DATETIME,
      redeemedDate DATETIME,
      userSender TEXT,
      userRecipient TEXT
    );

    CREATE TABLE IF NOT EXISTS users (
       userId TEXT PRIMARY KEY,
        firstName TEXT,
        lastName TEXT,
        imgUrl TEXT,
        deviceInfo TEXT
    );

       CREATE TABLE IF NOT EXISTS wallet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId TEXT,
        cryptoBalance TEXT,
        cashBalance TEXT
    );

     CREATE TABLE IF NOT EXISTS transactions (
      transactionId INTEGER PRIMARY KEY AUTOINCREMENT,
      interactionType INTEGER,
      amount TEXT,  
      coinStatus INTEGER,
      expirationDate DATETIME,  
      capturedDate DATETIME,  
      createDate DATETIME,  
      user TEXT
    );
  `

  db.exec(createTablesSQL, (err) => {
    if (err) {
        console.error("Error creating tables:", err);
    } else {
        preloadData(); // Insert preloaded data after table creation
    }
});

const preloadData = () => {
  
  // Insert users data
  users.forEach(user => {
      const insertUserSQL = `
      INSERT OR IGNORE INTO users (userId, firstName, lastName, imgUrl, deviceInfo) 
      VALUES (?, ?, ?,?,?)
      `;
      db.run(insertUserSQL, [user.userId, user.firstName, user.lastName, user.imgUrl, JSON.stringify(user.deviceInfo)], (err) => {
          if (err) {
              console.error("Error inserting user:", err);
          }
      });

      const insertBalanceSQL = `INSERT OR IGNORE INTO wallet (userId, cryptoBalance, cashBalance) VALUES(?,?,?)`;
      db.run(insertBalanceSQL, [user.userId, 100, 100], (err) => {
        if (err) {
            console.error("Error inserting user balance:", err);
        }
    });
  });

  // Insert transactions data
  transactions.forEach(transaction => {
      const insertTransactionSQL = `
      INSERT OR IGNORE INTO transactions (
          transactionId, interactionType, amount, coinStatus, expirationDate, capturedDate, createDate, user
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      db.run(insertTransactionSQL, [
          transaction.transactionId, 
          transaction.interactionType, 
          transaction.amount, 
          transaction.coinStatus,
          transaction.expirationDate,
          transaction.capturedDate,
          transaction.createDate,
          JSON.stringify(transaction.user)
      ], (err) => {
          if (err) {
              console.error("Error inserting transaction:", err);
          } 
      });
  });

  coinsDb.forEach(coin => {
    const insertCoinSQL = `
    INSERT OR IGNORE INTO coins (coinId, coinStatus, latitude, longitude, message, cashAmount, creationDate, expirationDate, redeemedDate, userSender, userRecipient) 
    VALUES (?, ?, ?, ?,?,?,?,?,?,?,?)
    `;
    db.run(insertCoinSQL, [coin.coinId, coin.coinStatus, coin.latitude, coin.longitude, coin.message, coin.cashAmount, coin.creationDate, coin.expirationDate, coin.redeemedDate, JSON.stringify(coin.userSender), JSON.stringify(coin.userRecipient)], (err) => {
        if (err) {
            console.error("Error inserting coin:", err);
        } 
    });
});
};
export default db;
