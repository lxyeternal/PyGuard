import json
import os
import time
import logging
from openai import AzureOpenAI
from typing import List, Dict, Any, Optional
from pathlib import Path
from config import Config


class SocketAI:
    def __init__(self, max_attempts: int = 5):
        self.client = AzureOpenAI(
            api_key=Config.AZURE_OPENAI_API_KEY,
            api_version=Config.AZURE_OPENAI_API_VERSION,
            azure_endpoint=Config.AZURE_OPENAI_ENDPOINT
        )
        self.prompts = self._load_prompts()
        self.max_attempts = max_attempts
    
    def _load_prompts(self) -> Dict[str, str]:
        """加载所有提示词文件"""
        prompts = {}
        # 使用相对于当前文件的路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        prompt_dir = os.path.join(current_dir, "prompts")
        
        prompts['step1'] = Path(os.path.join(prompt_dir, "step1_initial.txt")).read_text(encoding='utf-8')
        prompts['step2'] = Path(os.path.join(prompt_dir, "step2_critical.txt")).read_text(encoding='utf-8')
        prompts['step3'] = Path(os.path.join(prompt_dir, "step3_final.txt")).read_text(encoding='utf-8')
        
        return prompts
    
    def _call_llm(self, model: str, system_prompt: str, user_prompt: str, 
                  temperature: float, top_p: float) -> str:
        """调用LLM API，带重试机制"""
        wait_time = 20
        attempt = 0
        
        while attempt < self.max_attempts:
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=temperature,
                    top_p=top_p
                )
                return response.choices[0].message.content
            except Exception as e:
                logging.warning(f"LLM调用尝试 {attempt + 1}: 发生错误: {e}")
                attempt += 1
                if attempt < self.max_attempts:
                    time.sleep(wait_time)
                    wait_time += 5  # 每次失败后增加等待时间
        
        # 如果所有尝试都失败，返回空字符串或抛出异常
        logging.error(f"LLM调用失败，已尝试 {self.max_attempts} 次")
        return ""
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """解析JSON响应，处理可能的格式错误"""
        # 检查是否为空响应（重试失败的情况）
        if not response or response.strip() == "":
            return {"error": "Empty response", "raw_response": response}
        
        # 去除可能的非JSON文本
        response = response.strip()
        
        # 如果响应被包裹在```json和```之间
        if response.startswith("```json") and response.endswith("```"):
            response = response[7:-3].strip()
        elif response.startswith("```") and response.endswith("```"):
            response = response[3:-3].strip()
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # 尝试修复常见的JSON错误
            print(f"JSON解析错误，原始响应：{response}")
            return {"error": "JSON parse error", "raw_response": response}
    
    def step1_initial_reports(self, code: str, use_strong_model: bool = False) -> List[Dict[str, Any]]:
        """Step 1: 生成初始报告"""
        # 选择模型
        model = Config.STRONG_MODEL if use_strong_model else Config.STANDARD_MODEL
        # 确定报告数量
        count = Config.STRONG_MODEL_REPORTS_COUNT if use_strong_model else Config.STANDARD_MODEL_REPORTS_COUNT
        
        reports = []
        user_prompt = f"{code}\n\n{Config.USER_PROMPT}"
        
        for i in range(count):
            print(f"  生成初始报告 {i+1}/{count} (使用 {model})...")
            response = self._call_llm(
                model=model,
                system_prompt=self.prompts['step1'],
                user_prompt=user_prompt,
                temperature=Config.STEP1_PARAMS["temperature"],
                top_p=Config.STEP1_PARAMS["top_p"]
            )
            report = self._parse_json_response(response)
            report['report_number'] = i + 1
            reports.append(report)
        
        return reports
    
    def step2_critical_reports(self, initial_reports: List[Dict[str, Any]], 
                              code: str, use_strong_model: bool = False) -> List[Dict[str, Any]]:
        """Step 2: 生成关键报告"""
        model = Config.STRONG_MODEL if use_strong_model else Config.STANDARD_MODEL
        count = Config.STRONG_MODEL_REPORTS_COUNT if use_strong_model else Config.STANDARD_MODEL_REPORTS_COUNT
        
        # 准备输入：所有初始报告 + 原始代码
        reports_str = json.dumps(initial_reports, indent=2)
        user_prompt = f"Original Code:\n{code}\n\nReports to review:\n{reports_str}"
        
        critical_reports = []
        for i in range(count):
            print(f"  生成关键报告 {i+1}/{count} (使用 {model})...")
            response = self._call_llm(
                model=model,
                system_prompt=self.prompts['step2'],
                user_prompt=user_prompt,
                temperature=Config.STEP2_PARAMS["temperature"],
                top_p=Config.STEP2_PARAMS["top_p"]
            )
            # Step 2 可能不是JSON格式，保存原始响应
            # 处理空响应情况
            if not response or response.strip() == "":
                response = "ERROR: LLM调用失败，无法生成关键报告"
            
            critical_reports.append({
                "review": response,
                "model": model,
                "report_number": i + 1
            })
        
        return critical_reports
    
    def step3_final_report(self, critical_reports: List[Dict[str, Any]], 
                          code: str, use_strong_model: bool = False) -> Dict[str, Any]:
        """Step 3: 生成最终报告"""
        model = Config.STRONG_MODEL if use_strong_model else Config.STANDARD_MODEL
        
        # 准备输入：所有关键报告 + 原始代码 + 初始系统提示
        reports_str = json.dumps(critical_reports, indent=2)
        combined_system_prompt = f"{self.prompts['step3']}\n\n{self.prompts['step1']}"
        user_prompt = f"Original Code:\n{code}\n\nCritical Reports:\n{reports_str}"
        
        print(f"  生成最终报告 (使用 {model})...")
        response = self._call_llm(
            model=model,
            system_prompt=combined_system_prompt,
            user_prompt=user_prompt,
            temperature=Config.STEP3_PARAMS["temperature"],
            top_p=Config.STEP3_PARAMS["top_p"]
        )
        
        final_report = self._parse_json_response(response)
        final_report['model'] = model
        return final_report
    
    def analyze_file(self, file_path: str, use_strong_model: bool = False) -> Dict[str, Any]:
        """分析单个文件的完整工作流程"""
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        print(f"\n开始分析文件: {file_path}")
        print(f"使用模型: {Config.STRONG_MODEL if use_strong_model else Config.STANDARD_MODEL}")
        
        # Step 1: 初始报告
        print("\nStep 1: 生成初始报告...")
        initial_reports = self.step1_initial_reports(code, use_strong_model)
        
        # Step 2: 关键报告
        print("\nStep 2: 生成关键报告...")
        critical_reports = self.step2_critical_reports(initial_reports, code, use_strong_model)
        
        # Step 3: 最终报告
        print("\nStep 3: 生成最终报告...")
        final_report = self.step3_final_report(critical_reports, code, use_strong_model)
        
        # 添加文件信息和所有中间报告
        final_report['file_path'] = file_path
        final_report['initial_reports'] = initial_reports
        final_report['critical_reports'] = critical_reports
        
        # 判断文件是否恶意
        if 'malware' in final_report:
            final_report['is_malicious'] = final_report['malware'] > Config.MALWARE_THRESHOLD
        
        return final_report
    
    def analyze_package(self, package_dir: str, use_strong_model: bool = False) -> Dict[str, Any]:
        """分析整个包"""
        results = {
            "package_dir": package_dir,
            "model": Config.STRONG_MODEL if use_strong_model else Config.STANDARD_MODEL,
            "files": [],
            "is_malicious": False,
            "malicious_files": [],
            "summary": {
                "total_files": 0,
                "analyzed_files": 0,
                "malicious_files": 0
            }
        }
        
        # 遍历所有JS文件
        js_files = []
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(os.path.join(root, file))
        
        results["summary"]["total_files"] = len(js_files)
        
        # 分析每个文件
        for i, js_file in enumerate(js_files):
            print(f"\n进度: {i+1}/{len(js_files)}")
            try:
                file_report = self.analyze_file(js_file, use_strong_model)
                results["files"].append(file_report)
                results["summary"]["analyzed_files"] += 1
                
                # 检查恶意评分
                if file_report.get("is_malicious", False):
                    results["is_malicious"] = True
                    results["malicious_files"].append({
                        "file": js_file,
                        "malware_score": file_report.get("malware", 0),
                        "conclusion": file_report.get("conclusion", "")
                    })
                    results["summary"]["malicious_files"] += 1
            
            except Exception as e:
                print(f"分析文件 {js_file} 时出错: {str(e)}")
                results["files"].append({
                    "file_path": js_file,
                    "error": str(e),
                    "is_malicious": False
                })
        
        return results