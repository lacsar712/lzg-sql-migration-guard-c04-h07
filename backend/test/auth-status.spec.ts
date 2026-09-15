import { INestApplication, ValidationPipe } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { ApiController } from '../src/api/api.controller';
import { AuthGuard } from '../src/auth/auth.guard';
import { login } from '../src/auth/auth.store';
import { RuleEngineService } from '../src/rule-engine/rule-engine.service';
import { ReportService } from '../src/report/report.service';
import { HistoryService } from '../src/history/history.service';

/**
 * 状态码分层回归测试：
 *  - 未认证            -> 401
 *  - 已认证但角色不足   -> 403（且不会写入历史）
 *  - 角色足够但参数非法 -> 400
 */
describe('API 状态码分层（认证/授权/参数校验）', () => {
  let app: INestApplication;
  let baseUrl: string;
  let historySave: jest.Mock;

  const engineMock = {
    analyze: jest.fn().mockReturnValue({
      ok: true,
      dialect: 'postgresql',
      sqlSummary: 'SELECT 1',
      findings: [],
    }),
    listRules: jest.fn().mockReturnValue([]),
  };
  const reportMock = {
    toResponse: jest.fn((result: unknown, id: string) => ({
      ...(result as object),
      id,
    })),
    summarizeFindings: jest.fn().mockReturnValue({}),
  };

  beforeAll(async () => {
    historySave = jest.fn().mockResolvedValue({ id: 'test-history-id' });
    const moduleRef = await Test.createTestingModule({
      controllers: [ApiController],
      providers: [
        // 与 AuthModule 一致：全局注册真实的 AuthGuard
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: RuleEngineService, useValue: engineMock },
        { provide: ReportService, useValue: reportMock },
        {
          provide: HistoryService,
          useValue: { save: historySave, list: jest.fn(), getById: jest.fn() },
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    // 与 main.ts 一致的全局校验管道
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
    await app.listen(0);
    const address = app.getHttpServer().address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    historySave.mockClear();
  });

  function postAnalyze(token: string | null, body: unknown) {
    return fetch(`${baseUrl}/v1/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
  }

  const VALID_BODY = { dialect: 'postgresql', sql: 'SELECT 1;' };

  it('reader 调 analyze -> 403，且不写入历史', async () => {
    const reader = login('reader', 'read123456');
    expect(reader).not.toBeNull();

    const res = await postAnalyze(reader!.token, VALID_BODY);
    expect(res.status).toBe(403);
    // 业务约束：reader 永远不能写入历史
    expect(engineMock.analyze).not.toHaveBeenCalled();
    expect(historySave).not.toHaveBeenCalled();
  });

  it('analyst 发空 SQL -> 400', async () => {
    const analyst = login('analyst', 'sql123456');
    const res = await postAnalyze(analyst!.token, {
      dialect: 'postgresql',
      sql: '',
    });
    expect(res.status).toBe(400);
    expect(historySave).not.toHaveBeenCalled();
  });

  it('analyst 发非法 body（缺 sql / 非法 dialect）-> 400', async () => {
    const analyst = login('analyst', 'sql123456');

    const missingSql = await postAnalyze(analyst!.token, {
      dialect: 'postgresql',
    });
    expect(missingSql.status).toBe(400);

    const badDialect = await postAnalyze(analyst!.token, {
      dialect: 'oracle',
      sql: 'SELECT 1;',
    });
    expect(badDialect.status).toBe(400);

    expect(historySave).not.toHaveBeenCalled();
  });

  it('analyst 合法请求 -> 201，且写入历史', async () => {
    const analyst = login('analyst', 'sql123456');
    const res = await postAnalyze(analyst!.token, VALID_BODY);
    expect(res.status).toBe(201);
    expect(historySave).toHaveBeenCalledTimes(1);
  });

  it('未携带令牌 -> 401', async () => {
    const res = await postAnalyze(null, VALID_BODY);
    expect(res.status).toBe(401);
    expect(historySave).not.toHaveBeenCalled();
  });
});
