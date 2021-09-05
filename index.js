const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const app = express()
const fs = require('fs')
const bcrypt = require('bcrypt')
const { emit } = require('process')
const saltRounds = 10

app.use(express.json())
app.use(cors())

app.get('/findall', function (req, res) {
    const tel = req.query.tel
    const username = req.query.username
    let email = req.query.email
    let result = false
    let index
    // console.log(req)
    const data = JSON.parse(
        fs.readFileSync('data/loginPage.json').toString('utf-8')
    )
    Object.keys(data.users).forEach((k) => {
        const Data = data.users[k]
        const cheaktel = Data.tel
        const cheakusername = Data.username
        const cheakemail = Data.email
        if (tel == cheaktel && username == cheakusername) {
            result = true
            email = cheakemail
        }
    })
    // console.log(data.users)
    res.send({ result, email })
})

app.get('/cheaktoken', function (req, res) {
    const token = req.headers['token'] // client에게서 받은 토큰
    const result = false
    /* 토큰이 없으면 403 에러 응답 처리 */
    if (!token) {
        return res.status(403).json({
            success: false,
            message: 'not logged in',
        })
    }
    /* 토큰 유효성 검사 */
    const p = new Promise((resolve, reject) => {
        jwt.verify(token, 'SeCrEtKeYfOrHaShInG', (err, decoded) => {
            if (err) reject(err)
            else resolve(decoded)
        })
    })
    /* 유효하지 않은 토큰으로 403 에러 처리 */
    const onError = (error) => {
        res.status(403).json({
            success: false,
            message: error.message,
        })
    }
    p.then((decoded) => {
        res.send(decoded.name)
    }).catch(onError)
})

app.post('/login', function (req, res) {
    const data = JSON.parse(
        fs.readFileSync('data/loginPage.json').toString('utf-8')
    )
    let result = true
    const email = req.body.email
    const password = req.body.password
    const target = data.users.find((o) => o.email == email)
    if (target == undefined || !bcrypt.compareSync(password, target.password)) {
        result = false
    }
    const getToken = () => {
        return new Promise((resolve, reject) => {
            jwt.sign(
                {
                    name: `${target.username}`,
                },

                'SeCrEtKeYfOrHaShInG', // secrec Key

                {
                    expiresIn: '7d',
                    issuer: 'inyongTest', // options
                    subject: 'userInfo',
                },

                function (err, token) {
                    if (err) reject(err)
                    // callback
                    else resolve(token)
                }
            )
        })
    }
    getToken().then((token) => {
        res.send({ token, result })
    })
})

app.post('/signup', function (req, res) {
    const data = JSON.parse(
        fs.readFileSync('data/loginPage.json').toString('utf-8')
    )
    const email = req.body.email
    let result = false
    req.body.password = bcrypt.hashSync(req.body.password, saltRounds)
    data.users.sort((a, b) => {
        return a.index - b.index
    })
    req.body.index = data.users[data.users.length - 1].index + 1
    Object.keys(data.users).forEach((k) => {
        const Data = data.users[k]
        const cheakemail = Data.email
        if (cheakemail == email) result = true
    })
    if (!result == true) data.users.push(req.body)
    fs.writeFileSync('data/loginPage.json', JSON.stringify(data))
    res.send({ success: !result, index: req.body.index })
})

app.delete('/delete', function (req, res) {
    let success = false
    let errorMsg
    const data = JSON.parse(
        fs.readFileSync('data/loginPage.json').toString('utf-8')
    )
    const email = req.body.email
    const passwordHash = req.body.password
    const target = data.users.find((o) => o.email == email)
    if (target) {
        if (bcrypt.compareSync(passwordHash, target.password)) {
            data.users.splice(data.users.indexOf(target), 1)
            success = true
        } else {
            errorMsg = '비밀번호가 잘못 됨'
        }
    } else {
        errorMsg = '해당 게시물을 찾을 수 없음'
    }
    fs.writeFileSync('data/loginPage.json', JSON.stringify(data))
    res.send({ success, errorMsg })
})

app.put('/put', function (req, res) {
    let success = false
    let errorMsg
    const data = JSON.parse(
        fs.readFileSync('data/loginPage.json').toString('utf-8')
    )
    const email = req.body.email
    const passwordHash = req.body.password
    const changePasswordHash = bcrypt.hashSync(
        req.body.changePassword,
        saltRounds
    )
    const target = data.users.find((o) => o.email == email)
    if (target) {
        if (bcrypt.compareSync(passwordHash, target.password)) {
            target.password = changePasswordHash
            success = true
            fs.writeFileSync('data/loginPage.json', JSON.stringify(data))
        } else {
            errorMsg = '비밀번호를 잘못 입력하셨습니다. 다시 입력하여 주세요.'
        }
    } else {
        errorMsg = '잘못된 이메일 주소를 입력하셨습니다. 다시 입력하여 주세요.'
    }
    res.send({ success, errorMsg })
})

app.listen(3714)
