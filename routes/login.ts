/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Request, Response, NextFunction } from 'express';
import * as models from '../models/index';
import { User } from '../data/types';
import { BasketModel } from '../models/basket';
import { UserModel } from '../models/user';
import * as challengeUtils from '../lib/challengeUtils';
import config from 'config';
import { challenges } from '../data/datacache';
import * as utils from '../lib/utils';
import * as security from '../lib/insecurity';
import { users } from '../data/datacache';
import rateLimit from 'express-rate-limit';

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Limite de 10 tentativas de login por IP
  message: 'Muitas tentativas de login. Por favor, tente novamente mais tarde.'
});

module.exports = function login() {
  function afterLogin(user: { data: User; bid: number }, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user); // vuln-code-snippet hide-line
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user);
        user.bid = basket.id; // keep track of original basket
        security.authenticatedUsers.put(token, user);
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } });
      })
      .catch((error: Error) => {
        next(error);
      });
  }

  return [
    loginRateLimiter,
    (req: Request, res: Response, next: NextFunction) => {
      verifyPreLoginChallenges(req); // vuln-code-snippet hide-line
      models.sequelize
        .query('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL', {
          replacements: [req.body.email || '', security.hash(req.body.password || '')],
          model: UserModel,
          plain: true,
        })
        .then((authenticatedUser: any) => {
          const user = utils.queryResultToJson(authenticatedUser);
          if (user.data?.id && user.data.totpSecret !== '') {
            res.status(401).json({
              status: 'totp_token_required',
              data: {},
            });
          } else {
            afterLogin({ data: user.data, bid: 0 }, res, next);
          }
        })
        .catch((error: Error) => {
          next(error);
        });
    },
  ];
};

function verifyPostLoginChallenges(user: { data: User }) {
  challengeUtils.solveIf(challenges.loginAdminChallenge, () => {
    return user.data.id === users.admin.id;
  });
  challengeUtils.solveIf(challenges.loginJimChallenge, () => {
    return user.data.id === users.jim.id;
  });
  challengeUtils.solveIf(challenges.loginBenderChallenge, () => {
    return user.data.id === users.bender.id;
  });
  challengeUtils.solveIf(challenges.ghostLoginChallenge, () => {
    return user.data.id === users.chris.id;
  });
  if (
    challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) &&
    user.data.email === 'acc0unt4nt@' + config.get<string>('application.domain') &&
    user.data.role === 'accounting'
  ) {
    UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } })
      .then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge);
        }
      })
      .catch(() => {});
  }
}

function verifyPreLoginChallenges(req: Request) {
  challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config.get<string>('application.domain') && req.body.password === 'admin123' })
  challengeUtils.solveIf(challenges.loginSupportChallenge, () => { return req.body.email === 'support@' + config.get<string>('application.domain') && req.body.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P' })
  challengeUtils.solveIf(challenges.loginRapperChallenge, () => { return req.body.email === 'mc.safesearch@' + config.get<string>('application.domain') && req.body.password === 'Mr. N00dles' })
  challengeUtils.solveIf(challenges.loginAmyChallenge, () => { return req.body.email === 'amy@' + config.get<string>('application.domain') && req.body.password === 'K1f.....................' })
  challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => { return req.body.email === 'J12934@' + config.get<string>('application.domain') && req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB' })
  challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return req.body.email === 'bjoern.kimminich@gmail.com' && req.body.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
}
