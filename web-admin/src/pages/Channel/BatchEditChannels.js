import React, {useEffect, useRef, useState} from 'react';
import {useNavigate, useParams} from 'react-router-dom';
import {API, isMobile, showError, showInfo, showSuccess, verifyJSON} from '../../helpers';
import {CHANNEL_OPTIONS} from '../../constants';
import Title from "@douyinfe/semi-ui/lib/es/typography/title";
import {SideSheet, Space, Spin, Button, Input, Typography, Select, TextArea, Checkbox, Banner,AutoComplete} from "@douyinfe/semi-ui";

const MODEL_MAPPING_EXAMPLE = {
    'gpt-3.5-turbo-0301': 'gpt-3.5-turbo',
    'gpt-4-0314': 'gpt-4',
    'gpt-4-32k-0314': 'gpt-4-32k'
};

function type2secretPrompt(type) {
    // inputs.type === 15 ? '按照如下格式输入：APIKey|SecretKey' : (inputs.type === 18 ? '按照如下格式输入：APPID|APISecret|APIKey' : '请输入渠道对应的鉴权密钥')
    switch (type) {
        case 15:
            return '按照如下格式输入：APIKey|SecretKey';
        case 18:
            return '按照如下格式输入：APPID|APISecret|APIKey';
        case 22:
            return '按照如下格式输入：APIKey-AppId，例如：fastgpt-0sp2gtvfdgyi4k30jwlgwf1i-64f335d84283f05518e9e041';
        case 23:
            return '按照如下格式输入：AppId|SecretId|SecretKey';
        default:
            return '请输入渠道对应的鉴权密钥';
    }
}

const BatchEditChannels = (props) => {
    
    const {
        visible,
        handleClose,
        editingChannelIds, // 使用编辑渠道的ID数组代替单个渠道ID
        refresh,
    } = props;

    const handleCancel = () => {
        props.handleClose()
    };
    const originInputs = {
        openai_organization: '',
        model_mapping: '',
        headers: '',
        models: [],
        auto_ban: 1,
        is_image_url_enabled: 0,
        model_test: '', 
        tested_time:'',
        priority:'',
        weight:'',
        groups: ['default']
    };
    // const [autoBan, setAutoBan] = useState(true);
    const [inputs, setInputs] = useState(originInputs);
    const [originModelOptions, setOriginModelOptions] = useState([]);
    const [modelOptions, setModelOptions] = useState([]);
    const [groupOptions, setGroupOptions] = useState([]);
    const [basicModels, setBasicModels] = useState([]);
    const [fullModels, setFullModels] = useState([]);
    const [customModel, setCustomModel] = useState('');
    const [restartDelay, setRestartDelay] = useState(0); 
    const [weight, setWeight] = useState(0);
    const [istools, setIstools] = useState(true);
    const [isimageurenabled, setIsImageURLEnabled] = useState(false);
    const [loading, setLoading] = useState(false);
    const [autoBan, setAutoBan] = useState(true);
    const [rateLimited, setRateLimited] = useState(false);
    const [priority, setPriority] = useState(0);
    const [modelTest, setModelTest] = useState('gpt-3.5-turbo');
    const handleInputChange = (name, value) => {
        setInputs((inputs) => ({...inputs, [name]: value}));
        if (name === 'type' && inputs.models.length === 0) {
            let localModels = [];
            setInputs((inputs) => ({...inputs, models: localModels}));
        }
        //setAutoBan
    };
    

    const fetchModels = async () => {
        try {
            let res = await API.get(`/api/channel/models`);
            let localModelOptions = res.data.data.map((model) => ({
                label: model.id,
                value: model.id
            }));
            setOriginModelOptions(localModelOptions);
            setFullModels(res.data.data.map((model) => model.id));
            setBasicModels(res.data.data.filter((model) => {
                return model.id.startsWith('gpt-3') || model.id.startsWith('gpt-4') || model.id.startsWith('text-');
            }).map((model) => model.id));
        } catch (error) {
            showError(error.message);
        }
    };

    const fetchGroups = async () => {
        try {
            let res = await API.get(`/api/group/`);
            setGroupOptions(res.data.data.map((group) => ({
                label: group,
                value: group
            })));
        } catch (error) {
            showError(error.message);
        }
    };

    useEffect(() => {
        setModelOptions(originModelOptions);
    }, [originModelOptions]);

    useEffect(() => {
        // 当editingChannelIds改变时，获取第一个channelId的信息，并设置到表单
        if (editingChannelIds.length > 0) {
            fetchChannelDataByID(editingChannelIds[0]);
        } else {
            // 如果没有选择任何channel，则可以将表单重置为默认值或者其他指定值
            setInputs(originInputs);
        }
        fetchModels().then();
        fetchGroups().then();
    }, [editingChannelIds]); // 注意将 editingChannelIds 加入依赖列表
    
    // 基于channel ID获取channel数据的函数
    const fetchChannelDataByID = async (channelId) => {
        setLoading(true);
        try {
            const response = await API.get(`/api/channel/${channelId}`);
            if (response.data && response.data.success) {
                const channelData = response.data.data;
                setInputs({
                    ...inputs,
                    // 此处根据实际后端返回的数据结构进行调整
                    models: channelData.models ? channelData.models.split(',') : [],
                    auto_ban: channelData.auto_ban || 1,
                    is_image_url_enabled: channelData.is_image_url_enabled || 1,
                    model_test: channelData.model_test || 'gpt-3.5-turbo',
                    tested_time: channelData.tested_time || 0,
                    priority: channelData.priority || 0,
                    weight: channelData.weight || 0,
                    groups: channelData.groups ? channelData.groups.split(',') : ['default'],
                    model_mapping: channelData.model_mapping || '',
                    headers: channelData.headers || '',

                });
            } else {
                showError('获取渠道信息失败');
            }
        } catch (error) {
            console.error(error);
            showError('获取渠道信息时发生错误');
        } finally {
            setLoading(false);
        }
    };
    

    const submit = async () => {
        let failCount = 0;
        if (inputs.models.length === 0) {
            showInfo('请至少选择一个模型！');
            return;
        }
        
        if (inputs.model_mapping !== '' && !verifyJSON(inputs.model_mapping)) {
            showInfo('模型映射必须是合法的 JSON 格式！');
            return;
        }
        if (inputs.headers !== '' && !verifyJSON(inputs.headers)) {
            showInfo('模型映射必须是合法的 JSON 格式！');
            return;
        }
        let localInputs = {...inputs};
         // 将 autoBan 状态转换为对应的整数值并添加到 localInputs 中
        localInputs.auto_ban = autoBan ? 1 : 0;
        localInputs.tested_time = restartDelay;
        localInputs.priority = priority;
        localInputs.weight = weight;
        localInputs.rate_limited = rateLimited;
        localInputs.is_tools = istools;
        localInputs.is_image_url_enabled = isimageurenabled ? 1 : 0;
        
        if (localInputs.base_url && localInputs.base_url.endsWith('/')) {
            localInputs.base_url = localInputs.base_url.slice(0, localInputs.base_url.length - 1);
        }
        if (localInputs.type === 3 && localInputs.other === '') {
            localInputs.other = '2023-06-01-preview';
        }
        if (localInputs.type === 18 && localInputs.other === '') {
            localInputs.other = 'v2.1';
        }
        // 如果 model_test 为空，则设置默认值
        if (!localInputs.model_test) {
            localInputs.model_test = 'gpt-3.5-turbo';
        }

        localInputs.models = localInputs.models.join(',');
        localInputs.group = localInputs.groups.join(',');
    
        for (let channelId of editingChannelIds) {
            try {
                const response = await API.put(`/api/channel/`, {...localInputs, id: parseInt(channelId)});
                if (!response.data.success) {
                    failCount++;
                }
            } catch (error) {
                failCount++;
                console.error(`Failed to update channel ${channelId}: `, error);
            }
        }
    
        if (failCount === 0) {
            showSuccess('All selected channels have been updated successfully.');
        } else {
            showError(`${failCount} channels failed to update.`);
        }
    
        setLoading(false);
        handleClose(); // 关闭编辑界面
        refresh(); // 刷新数据展示
    };
    
    



    const addCustomModel = () => {
        if (customModel.trim() === '') return;                // 确保自定义模型非空
        if (inputs.models.includes(customModel)) return;      // 确保未重复添加
    
        // 更新输入模型数组（无需修改选项，除非确实需要显示新模型）
        handleInputChange('models', [...inputs.models, customModel]);
        
        // 清空自定义模型输入（重置自定义模型输入字段）
        setCustomModel('');
    };

    return (
        <>
            <SideSheet
                maskClosable={false}
                placement={'left'}
                title={<Title level={3}>{'批量更新渠道信息'}</Title>}
                headerStyle={{borderBottom: '1px solid var(--semi-color-border)'}}
                bodyStyle={{borderBottom: '1px solid var(--semi-color-border)'}}
                visible={props.visible}
                footer={
                    <div style={{display: 'flex', justifyContent: 'flex-end'}}>
                        <Space>
                            <Button theme='solid' size={'large'} onClick={submit}>提交</Button>
                            <Button theme='solid' size={'large'} type={'tertiary'} onClick={handleCancel}>取消</Button>
                        </Space>
                    </div>
                }
                closeIcon={null}
                onCancel={() => handleCancel()}
                width={isMobile() ? '100%' : 600}
            >
                <Spin spinning={loading}>
                    <div style={{marginTop: 10}}>
                        <Typography.Text strong>类型：</Typography.Text>
                    </div>
                    <Select
                        name='type'
                        required
                        optionList={CHANNEL_OPTIONS}
                        value={inputs.type}
                        onChange={value => handleInputChange('type', value)}
                        style={{width: '50%'}}
                    />
                    {
                        inputs.type === 3 && (
                            <>
                                <div style={{marginTop: 10}}>
                                    <Banner type={"warning"} description={
                                        <>
                                            注意，<strong>模型部署名称必须和模型名称保持一致</strong>，因为 One API 会把请求体中的
                                            model
                                            参数替换为你的部署名称（模型名称中的点会被剔除），<a target='_blank'
                                                                                              href='https://one-api/issues/133?notification_referrer_id=NT_kwDOAmJSYrM2NjIwMzI3NDgyOjM5OTk4MDUw#issuecomment-1571602271'>图片演示</a>。
                                        </>
                                    }>
                                    </Banner>
                                </div>
                                <div style={{marginTop: 10}}>
                                    <Typography.Text strong>AZURE_OPENAI_ENDPOINT：</Typography.Text>
                                </div>
                                <Input
                                    label='AZURE_OPENAI_ENDPOINT'
                                    name='azure_base_url'
                                    placeholder={'请输入 AZURE_OPENAI_ENDPOINT，例如：https://docs-test-001.openai.azure.com'}
                                    onChange={value => {
                                        handleInputChange('base_url', value)
                                    }}
                                    value={inputs.base_url}
                                    autoComplete='new-password'
                                />
                                <div style={{marginTop: 10}}>
                                    <Typography.Text strong>默认 API 版本：</Typography.Text>
                                </div>
                                <Input
                                    label='默认 API 版本'
                                    name='azure_other'
                                    placeholder={'请输入默认 API 版本，例如：2023-06-01-preview，该配置可以被实际的请求查询参数所覆盖'}
                                    onChange={value => {
                                        handleInputChange('other', value)
                                    }}
                                    value={inputs.other}
                                    autoComplete='new-password'
                                />
                            </>
                        )
                    }


                    <div style={{marginTop: 10}}>
                        <Typography.Text strong>分组：</Typography.Text>
                    </div>
                    <Select
                        placeholder={'请选择可以使用该渠道的分组'}
                        name='groups'
                        required
                        multiple
                        selection
                        allowAdditions
                        additionLabel={'请在系统设置页面编辑分组倍率以添加新的分组：'}
                        onChange={value => {
                            handleInputChange('groups', value)
                        }}
                        value={inputs.groups}
                        autoComplete='new-password'
                        optionList={groupOptions}
                    />
                    {
                        inputs.type === 18 && (
                            <>
                                <div style={{marginTop: 10}}>
                                    <Typography.Text strong>模型版本：</Typography.Text>
                                </div>
                                <Input
                                    name='other'
                                    placeholder={'请输入星火大模型版本，注意是接口地址中的版本号，例如：v2.1'}
                                    onChange={value => {
                                        handleInputChange('other', value)
                                    }}
                                    value={inputs.other}
                                    autoComplete='new-password'
                                />
                            </>
                        )
                    }
                    {
                        inputs.type === 28 && (
                            <>
                                <div style={{marginTop: 10}}>
                                    <Typography.Text strong>模型版本：</Typography.Text>
                                </div>
                                <Input
                                    name='other'
                                    placeholder={'请输入engine_id 例如（stable-diffusion-v1-6）'}
                                    onChange={value => {
                                        handleInputChange('other', value)
                                    }}
                                    value={inputs.other}
                                    autoComplete='new-password'
                                />
                            </>
                        )
                    }
                    {
                        inputs.type === 21 && (
                            <>
                                <div style={{marginTop: 10}}>
                                    <Typography.Text strong>知识库 ID：</Typography.Text>
                                </div>
                                <Input
                                    label='知识库 ID'
                                    name='other'
                                    placeholder={'请输入知识库 ID，例如：123456'}
                                    onChange={value => {
                                        handleInputChange('other', value)
                                    }}
                                    value={inputs.other}
                                    autoComplete='new-password'
                                />
                            </>
                        )
                    }
                    <div style={{marginTop: 10}}>
                        <Typography.Text strong>模型：</Typography.Text>
                    </div>
                    <Select
                        placeholder={'请选择该渠道所支持的模型'}
                        name='models'
                        required
                        multiple
                        selection
                        onChange={value => {
                            handleInputChange('models', value)
                        }}
                        value={inputs.models}
                        autoComplete='new-password'
                        optionList={modelOptions}
                    />
                    <div style={{lineHeight: '40px', marginBottom: '12px'}}>
                        <Space>
                            <Button type='primary' onClick={() => {
                                handleInputChange('models', basicModels);
                            }}>填入基础模型</Button>
                            <Button type='secondary' onClick={() => {
                                handleInputChange('models', fullModels);
                            }}>填入所有模型</Button>
                            <Button type='warning' onClick={() => {
                                handleInputChange('models', []);
                            }}>清除所有模型</Button>
                        </Space>
                        <Input
                            addonAfter={
                                <Button type='primary' onClick={addCustomModel}>填入</Button>
                            }
                            placeholder='输入自定义模型名称'
                            value={customModel}
                            onChange={(value) => {
                                setCustomModel(value);
                            }}
                        />
                    </div>
                    <div style={{marginTop: 10}}>
                        <Typography.Text strong>模型重定向：</Typography.Text>
                    </div>
                    <TextArea
                        placeholder={`此项可选，用于修改请求体中的模型名称，为一个 JSON 字符串，键为请求中模型名称，值为要替换的模型名称，例如：\n${JSON.stringify(MODEL_MAPPING_EXAMPLE, null, 2)}`}
                        name='model_mapping'
                        onChange={value => {
                            handleInputChange('model_mapping', value)
                        }}
                        autosize
                        value={inputs.model_mapping}
                        autoComplete='new-password'
                    />
                    <Typography.Text style={{
                        color: 'rgba(var(--semi-blue-5), 1)',
                        userSelect: 'none',
                        cursor: 'pointer'
                    }} onClick={
                        () => {
                            handleInputChange('model_mapping', JSON.stringify(MODEL_MAPPING_EXAMPLE, null, 2))
                        }
                    }>
                        填入模板
                    </Typography.Text>

                    <div style={{marginTop: 10, display: 'flex'}}>
                        <Space>
                            <Checkbox
                                name='auto_ban'
                                checked={autoBan}
                                onChange={() => setAutoBan(!autoBan)}
                                // onChange={handleInputChange}
                            />
                            <Typography.Text
                                strong>是否自动禁用（仅当自动禁用开启时有效），关闭后不会自动禁用该渠道：</Typography.Text>
                        </Space>
                    </div>
                    <div style={{marginTop: 10, display: 'flex'}}>
                        <Space>
                            <Checkbox
                                checked={rateLimited}
                                onChange={() => setRateLimited(!rateLimited)}
                            />
                            <Typography.Text strong>启用频率限制（开启后渠道每分钟限制三次）</Typography.Text>
                        </Space>
                    </div>
                    <div style={{marginTop: 10, display: 'flex'}}>
                        <Space>
                            <Checkbox
                                checked={istools}
                                onChange={() => setIstools(!istools)}
                            />
                            <Typography.Text strong>是否支持FC插件</Typography.Text>
                        </Space>
                    </div>
                    {
                        inputs.type === 2 && (
                            <div style={{marginTop: 10, display: 'flex'}}>
                                <Space>
                                    <Checkbox
                                        checked={isimageurenabled}
                                        onChange={() => setIsImageURLEnabled(!isimageurenabled)}
                                    />
                                    <Typography.Text strong>启用MJ图片原始地址</Typography.Text>
                                </Space>
                            </div>
                        )
                    }

                    <div style={{marginTop: 20, display: 'flex', alignItems: 'center'}}>
                        <div style={{flex: 1}}>
                                <Typography.Text>优先级：</Typography.Text>
                                <AutoComplete
                                    style={{ width: '100%', marginTop: 8 }}
                                    placeholder={'请选择或输入'}
                                    onChange={(value) => setPriority(Number(value))}
                                    onSelect={(value) => setPriority(Number(value))}
                                    value={String(priority)} 
                                    autoComplete='off'
                                    type='number'
                                    data={[
                                    { value: 0, label: '0' },
                                    { value: 3, label: '3' },
                                    { value: 5, label: '5' },
                                    { value: 7, label: '7' },
                                    ]}
                                />
                        </div>
                        <div style={{flex: 1,marginLeft: 20}}>
                                <Typography.Text>权重：</Typography.Text>
                                <AutoComplete
                                    style={{ width: '100%', marginTop: 8 }}
                                    placeholder={'请选择或输入'}
                                    onChange={(value) => setWeight(Number(value))}
                                    onSelect={(value) => setWeight(Number(value))}
                                    value={String(weight)} 
                                    autoComplete='off'
                                    type='number'
                                    data={[
                                    { value: 0, label: '0' },
                                    { value: 2, label: '2' },
                                    { value: 5, label: '5' },
                                    { value: 10, label: '10' },
                                    ]}
                                />
                        </div>
                        <div style={{flex: 1,marginLeft: 20}}>
                            <Typography.Text>重启：</Typography.Text>
                            <AutoComplete
                                style={{ width: '100%', marginTop: 8 }}
                                placeholder={'请选择或输入'}
                                onChange={(value) => setRestartDelay(Number(value))}
                                onSelect={(value) => setRestartDelay(Number(value))}
                                value={String(restartDelay)} 
                                autoComplete='off'
                                type='number'
                                data={[
                                { value: 0, label: '不重启' },
                                { value: 60, label: '一分钟' },
                                { value: 120, label: '两分钟' },
                                { value: 300, label: '五分钟' },
                                ]}
                            />
                        </div>
                        <div style={{flex: 1, marginLeft: 20}}>
                            <Typography.Text strong>自动测试模型：</Typography.Text>
                            <Select
                                placeholder={'请选择自动测试使用的模型'}
                                name='model_test'
                                onChange={value => handleInputChange('model_test', value)}
                                value={inputs.model_test}
                                optionList={inputs.models.map(model => ({ label: model, value: model }))}
                                style={{width: '100%'}}
                            />
                        </div>
                    </div>

                    <div style={{marginTop: 10}}>
                        <Typography.Text strong>自定义请求头：</Typography.Text>
                    </div>
                    <TextArea
                        placeholder={`例如：\n
                        {
                            “Referer”: “https://xxxcom/”
                        }`}
                        name='headers'
                        onChange={value => {
                            handleInputChange('headers', value)
                        }}
                        autosize
                        value={inputs.headers}
                        autoComplete='new-password'
                    />

                </Spin>
            </SideSheet>
        </>
    );
};

export default BatchEditChannels;