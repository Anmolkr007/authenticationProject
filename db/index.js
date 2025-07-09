const mongoose = require('mongoose')


const connectDb=async ()=>{
    try {
        await mongoose.connect(`${process.env.MONGO_URI}`);
        console.log('mongoDB connected')
    } catch (error) {
        console.log('ERROR while connecting mongoDB');
    }
}


module.exports = connectDb;